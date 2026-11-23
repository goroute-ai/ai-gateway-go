package a2a_test

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/a2a"
	"github.com/goroute-ai/ai-gateway-go/internal/a2a/pb"
	a2aspec "github.com/goroute-ai/ai-gateway-go/internal/a2a/spec"
	"github.com/goroute-ai/ai-gateway-go/internal/auth"
	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/security/network"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/proto"
)

func TestGRPCServer_A2AServiceLifecycle_AllRPCs(t *testing.T) {
	ctx := context.Background()

	mockUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/message:stream" || stringsHasAcceptSSE(r) {
			w.Header().Set("Content-Type", "text/event-stream")
			frame1, _ := json.Marshal(&a2aspec.StreamResponse{
				StatusUpdate: &a2aspec.TaskStatusUpdateEvent{
					TaskId:    "up_stream_1",
					ContextId: "ctx_stream_1",
					Status:    a2aspec.TaskStatus{State: a2aspec.TASKSTATEWORKING},
				},
			})
			frame2, _ := json.Marshal(&a2aspec.StreamResponse{
				StatusUpdate: &a2aspec.TaskStatusUpdateEvent{
					TaskId:    "up_stream_1",
					ContextId: "ctx_stream_1",
					Status: a2aspec.TaskStatus{
						State: a2aspec.TASKSTATECOMPLETED,
						Message: &a2aspec.Message{
							MessageId: "m_stream_done",
							Role:      a2aspec.ROLEAGENT,
							Parts:     []a2aspec.Part{a2aspec.NewTextPart("streamed done")},
						},
					},
				},
			})
			_, _ = w.Write([]byte("data: " + string(frame1) + "\n\ndata: " + string(frame2) + "\n\n"))
			return
		}
		w.Header().Set("Content-Type", "application/a2a+json")
		respObj := a2aspec.NewSendMessageResponseTask(&a2aspec.Task{
			Id: "up_task_1",
			Status: a2aspec.TaskStatus{
				State: a2aspec.TASKSTATECOMPLETED,
			},
			Artifacts: &[]a2aspec.Artifact{
				{
					ArtifactId: "art_1",
					Parts:      []a2aspec.Part{a2aspec.NewTextPart("gRPC agent task succeeded")},
				},
			},
		})
		outJSON, _ := json.Marshal(respObj)
		_, _ = w.Write(outJSON)
	}))
	defer mockUpstream.Close()

	repo := storage.NewMemoryRepository()
	vault, err := auth.NewVault("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	require.NoError(t, err)
	rbac := auth.NewRBACEngine(repo)
	netPolicy, err := network.NewPolicy(config.OutboundSSRFConfig{AllowPrivateNetworks: true, AllowInsecureHTTP: true})
	require.NoError(t, err)

	signer := a2a.NewGatewayCardSigner("gw-key-1", "ES256", nil, vault)
	verifier := a2a.NewUpstreamCardVerifier(nil)
	router := a2a.NewRouterService(repo, vault, rbac, netPolicy, nil, signer, verifier)
	authSvc := auth.NewService(repo, nil, "sk-gw-master-admin-secret-key", 10*time.Second, time.Minute)
	authResolver := auth.NewAuthResolver(auth.ResolverConfig{
		Service: authSvc,
		Repo:    repo,
		RBAC:    rbac,
	})

	orgID := "org_grpc_test"
	require.NoError(t, repo.CreateOrganization(ctx, &domain.Organization{ID: orgID, Name: "Test Org", IsActive: true}))

	extCardJSON, _ := json.Marshal(&a2aspec.AgentCard{
		Name:               "Extended Code Reviewer",
		Description:        "Authenticated extended skills",
		Version:            "1.0.0",
		DefaultInputModes:  []string{"text/plain"},
		DefaultOutputModes: []string{"text/plain"},
		Skills:             []a2aspec.AgentSkill{{Id: "deep-audit", Name: "Deep Audit", Description: "Deep check", Tags: []string{"sec"}}},
		SupportedInterfaces: []a2aspec.AgentInterface{
			{ProtocolBinding: "HTTP+JSON", ProtocolVersion: "1.0", Url: "https://upstream.internal/a2a"},
		},
	})
	agent := &domain.A2AAgent{
		ID:                    "agent_grpc_01",
		OrgID:                 orgID,
		Name:                  "Code Reviewer",
		Slug:                  "code-reviewer",
		EndpointURL:           mockUpstream.URL,
		ExtendedAgentCardJSON: string(extCardJSON),
		AuthType:              "none",
		TaskVisibilityMode:    domain.TaskVisibilityKeyStrict,
		IsActive:              true,
	}
	require.NoError(t, repo.CreateA2AAgent(ctx, agent))

	vk := &domain.VirtualKey{
		ID:                "vk_grpc_1",
		OrgID:             orgID,
		KeyHash:           auth.HashKey("sk-gw-grpc-secret-key-12345"),
		KeyPrefix:         "sk-gw-grpc",
		AllowedEndpoints:  []string{"*"},
		AllowedA2AAgents:  []string{"*"},
		AllowedMCPServers: []string{"*"},
		IsActive:          true,
		CreatedAt:         time.Now().UTC(),
	}
	require.NoError(t, repo.CreateVirtualKey(ctx, vk))

	lis := bufconn.Listen(1024 * 1024)
	grpcServer := grpc.NewServer()
	a2aGRPC := a2a.NewGRPCServer(router, authSvc, rbac)
	a2aGRPC.SetAuthResolver(authResolver)
	a2aGRPC.Register(grpcServer)
	go func() { _ = grpcServer.Serve(lis) }()
	defer grpcServer.Stop()

	conn, err := grpc.NewClient("passthrough://bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return lis.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err)
	defer conn.Close()

	client := pb.NewA2AServiceClient(conn)
	authedCtx := metadata.NewOutgoingContext(ctx, metadata.Pairs(
		"authorization", "Bearer sk-gw-grpc-secret-key-12345",
		"x-a2a-agent-slug", "code-reviewer",
	))

	// 1. SendMessage
	sendResp, err := client.SendMessage(authedCtx, &pb.SendMessageRequest{
		Message: &pb.Message{
			MessageId: "msg_grpc_1",
			Role:      pb.Role_ROLE_USER,
			Parts:     []*pb.Part{{Content: &pb.Part_Text{Text: "Review this diff"}}},
		},
	})
	require.NoError(t, err)
	task := sendResp.GetTask()
	require.NotNil(t, task)
	require.NotEmpty(t, task.Id)
	assert.Equal(t, pb.TaskState_TASK_STATE_COMPLETED, task.Status.State)
	taskID := task.Id

	// 2. GetTask
	gotTask, err := client.GetTask(authedCtx, &pb.GetTaskRequest{Id: taskID})
	require.NoError(t, err)
	assert.Equal(t, taskID, gotTask.Id)

	// 3. ListTasks
	listResp, err := client.ListTasks(authedCtx, &pb.ListTasksRequest{PageSize: proto.Int32(10)})
	require.NoError(t, err)
	require.NotEmpty(t, listResp.Tasks)

	// 4. Create/Get/List/Delete Push Notification Config
	pushResp, err := client.CreateTaskPushNotificationConfig(authedCtx, &pb.TaskPushNotificationConfig{
		TaskId: taskID,
		Url:    "https://webhook.internal/push",
	})
	require.NoError(t, err)
	assert.Equal(t, "https://webhook.internal/push", pushResp.Url)

	getPushResp, err := client.GetTaskPushNotificationConfig(authedCtx, &pb.GetTaskPushNotificationConfigRequest{
		TaskId: taskID,
		Id:     pushResp.Id,
	})
	require.NoError(t, err)
	assert.Equal(t, pushResp.Id, getPushResp.Id)

	listPushResp, err := client.ListTaskPushNotificationConfigs(authedCtx, &pb.ListTaskPushNotificationConfigsRequest{
		TaskId: taskID,
	})
	require.NoError(t, err)
	require.Len(t, listPushResp.Configs, 1)

	_, err = client.DeleteTaskPushNotificationConfig(authedCtx, &pb.DeleteTaskPushNotificationConfigRequest{
		TaskId: taskID,
		Id:     pushResp.Id,
	})
	require.NoError(t, err)

	// 5. GetExtendedAgentCard
	extCard, err := client.GetExtendedAgentCard(authedCtx, &pb.GetExtendedAgentCardRequest{})
	require.NoError(t, err)
	assert.Equal(t, "Extended Code Reviewer", extCard.Name)
	require.NotEmpty(t, extCard.Signatures)
	assert.NotEmpty(t, extCard.Signatures[0].Protected)

	// 6. SendStreamingMessage
	streamClient, err := client.SendStreamingMessage(authedCtx, &pb.SendMessageRequest{
		Message: &pb.Message{
			MessageId: "msg_grpc_stream_1",
			Role:      pb.Role_ROLE_USER,
			Parts:     []*pb.Part{{Content: &pb.Part_Text{Text: "Stream review"}}},
		},
	})
	require.NoError(t, err)
	var frames []*pb.StreamResponse
	for {
		fr, recvErr := streamClient.Recv()
		if recvErr == io.EOF {
			break
		}
		require.NoError(t, recvErr)
		frames = append(frames, fr)
	}
	assert.Len(t, frames, 2)
}

func stringsHasAcceptSSE(r *http.Request) bool {
	return r != nil && r.Header != nil && len(r.Header.Get("Accept")) > 0 && r.Header.Get("Accept")[0:17] == "text/event-stream"
}
