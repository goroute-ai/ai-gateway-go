package a2a_test

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/a2a"
	"github.com/goroute-ai/ai-gateway-go/internal/a2a/pb"
	"github.com/goroute-ai/ai-gateway-go/internal/auth"
	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/security/network"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/proto"
)

func TestGRPCServer_A2AServiceLifecycle(t *testing.T) {
	ctx := context.Background()

	// 1. Mock upstream HTTP agent that completes tasks
	mockUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		respObj := &pb.SendMessageResponse{
			Payload: &pb.SendMessageResponse_Task{
				Task: &pb.Task{
					Status: &pb.TaskStatus{
						State: pb.TaskState_TASK_STATE_COMPLETED,
					},
					Artifacts: []*pb.Artifact{
						{
							Name: "result",
							Parts: []*pb.Part{
								{Content: &pb.Part_Text{Text: "gRPC agent task succeeded"}},
							},
						},
					},
				},
			},
		}
		outJSON, _ := a2a.ProtoJSONMarshaler.Marshal(respObj)
		_, _ = w.Write(outJSON)
	}))
	defer mockUpstream.Close()

	// 2. Setup Dependencies
	repo := storage.NewMemoryRepository()
	vault, err := auth.NewVault("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatalf("vault: %v", err)
	}
	rbac := auth.NewRBACEngine(repo)
	netPolicy, err := network.NewPolicy(config.OutboundSSRFConfig{
		AllowPrivateNetworks: true,
		AllowInsecureHTTP:    true,
	})
	if err != nil {
		t.Fatalf("netPolicy: %v", err)
	}
	signer := a2a.NewGatewayCardSigner("gw-key-1", "ES256", nil, vault)
	verifier := a2a.NewUpstreamCardVerifier(nil)

	router := a2a.NewRouterService(repo, vault, rbac, netPolicy, nil, signer, verifier)
	authSvc := auth.NewService(repo, nil, "sk-gw-master-admin-secret-key", 10*time.Second, time.Minute)

	// 3. Register Agent & VirtualKey in Repository
	orgID := "org_grpc_test"
	_ = repo.CreateOrganization(ctx, &domain.Organization{
		ID:       orgID,
		Name:     "Test Org",
		IsActive: true,
	})
	agent := &domain.A2AAgent{
		ID:                 "agent_grpc_01",
		OrgID:              orgID,
		Name:               "Code Reviewer",
		Slug:               "code-reviewer",
		EndpointURL:        mockUpstream.URL,
		AuthType:           "none",
		TaskVisibilityMode: domain.TaskVisibilityKeyStrict,
		IsActive:           true,
	}
	if err := repo.CreateA2AAgent(ctx, agent); err != nil {
		t.Fatalf("create agent: %v", err)
	}

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
	_ = repo.CreateVirtualKey(ctx, vk)

	// 4. Start in-memory gRPC Server with bufconn
	bufferSize := 1024 * 1024
	lis := bufconn.Listen(bufferSize)

	grpcServer := grpc.NewServer()
	a2aGRPC := a2a.NewGRPCServer(router, authSvc, rbac)
	a2aGRPC.Register(grpcServer)

	go func() {
		_ = grpcServer.Serve(lis)
	}()
	defer grpcServer.Stop()

	// 5. Connect gRPC Client via bufconn
	dialer := func(context.Context, string) (net.Conn, error) {
		return lis.Dial()
	}

	conn, err := grpc.NewClient("passthrough://bufnet",
		grpc.WithContextDialer(dialer),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("dial bufconn: %v", err)
	}
	defer conn.Close()

	client := pb.NewA2AServiceClient(conn)

	// Context with metadata auth
	callMD := metadata.Pairs(
		"authorization", "Bearer sk-gw-grpc-secret-key-12345",
		"x-a2a-agent-slug", "code-reviewer",
	)
	authedCtx := metadata.NewOutgoingContext(ctx, callMD)

	// 6. Test SendMessage over gRPC
	sendResp, err := client.SendMessage(authedCtx, &pb.SendMessageRequest{
		Message: &pb.Message{
			MessageId: "msg_grpc_1",
			Role:      pb.Role_ROLE_USER,
			Parts: []*pb.Part{
				{Content: &pb.Part_Text{Text: "Review this diff"}},
			},
		},
	})
	if err != nil {
		t.Fatalf("grpc SendMessage failed: %v", err)
	}

	task := sendResp.GetTask()
	if task == nil || task.Id == "" {
		t.Fatalf("expected non-empty task in SendMessageResponse: %v", sendResp)
	}
	if task.Status.State != pb.TaskState_TASK_STATE_COMPLETED {
		t.Fatalf("expected completed task state, got: %v", task.Status.State)
	}
	taskID := task.Id

	// 7. Test GetTask over gRPC
	gotTask, err := client.GetTask(authedCtx, &pb.GetTaskRequest{Id: taskID})
	if err != nil {
		t.Fatalf("grpc GetTask failed: %v", err)
	}
	if gotTask.Id != taskID {
		t.Fatalf("task ID mismatch: %s != %s", gotTask.Id, taskID)
	}

	// 8. Test ListTasks over gRPC
	listResp, err := client.ListTasks(authedCtx, &pb.ListTasksRequest{PageSize: proto.Int32(10)})
	if err != nil {
		t.Fatalf("grpc ListTasks failed: %v", err)
	}
	if len(listResp.Tasks) == 0 {
		t.Fatalf("expected at least 1 task in ListTasks")
	}

	// 9. Test Push Notification Config over gRPC
	pushResp, err := client.CreateTaskPushNotificationConfig(authedCtx, &pb.TaskPushNotificationConfig{
		TaskId: taskID,
		Url:    "https://webhook.internal/push",
	})
	if err != nil {
		t.Fatalf("grpc CreateTaskPushNotificationConfig failed: %v", err)
	}
	if pushResp.Url != "https://webhook.internal/push" {
		t.Fatalf("push notification url mismatch: %s", pushResp.Url)
	}

	getPushResp, err := client.GetTaskPushNotificationConfig(authedCtx, &pb.GetTaskPushNotificationConfigRequest{
		TaskId: taskID,
	})
	if err != nil {
		t.Fatalf("grpc GetTaskPushNotificationConfig failed: %v", err)
	}
	if getPushResp.Url != "https://webhook.internal/push" {
		t.Fatalf("get push config url mismatch: %s", getPushResp.Url)
	}
}
