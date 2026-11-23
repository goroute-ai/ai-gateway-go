package a2a

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	pb "github.com/goroute-ai/ai-gateway-go/internal/a2a/pb"
	a2aspec "github.com/goroute-ai/ai-gateway-go/internal/a2a/spec"
	"github.com/goroute-ai/ai-gateway-go/internal/auth"
	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/observability"
	"github.com/goroute-ai/ai-gateway-go/internal/security/network"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type mockUpstreamGRPCAgent struct {
	pb.UnimplementedA2AServiceServer
	mu             sync.Mutex
	lastMD         metadata.MD
	canceledTaskID string
}

func (m *mockUpstreamGRPCAgent) recordMD(ctx context.Context) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		m.lastMD = md.Copy()
	}
}

func (m *mockUpstreamGRPCAgent) SendMessage(ctx context.Context, req *pb.SendMessageRequest) (*pb.SendMessageResponse, error) {
	m.recordMD(ctx)
	txt := ""
	if len(req.GetMessage().GetParts()) > 0 {
		txt = req.GetMessage().GetParts()[0].GetText()
	}
	meta, _ := structpb.NewStruct(map[string]any{
		"cost_micros": 330,
	})
	return &pb.SendMessageResponse{
		Payload: &pb.SendMessageResponse_Task{
			Task: &pb.Task{
				Id:        "up_grpc_task_01",
				ContextId: "ctx_grpc_01",
				Status: &pb.TaskStatus{
					State:     pb.TaskState_TASK_STATE_WORKING,
					Timestamp: timestamppb.Now(),
					Message: &pb.Message{
						MessageId: "msg_grpc_reply_01",
						Role:      pb.Role_ROLE_AGENT,
						Parts: []*pb.Part{
							{Content: &pb.Part_Text{Text: "gRPC upstream echo: " + txt}},
						},
					},
				},
				Metadata: meta,
			},
		},
	}, nil
}

func (m *mockUpstreamGRPCAgent) SendStreamingMessage(req *pb.SendMessageRequest, stream grpc.ServerStreamingServer[pb.StreamResponse]) error {
	m.recordMD(stream.Context())
	txt := ""
	if len(req.GetMessage().GetParts()) > 0 {
		txt = req.GetMessage().GetParts()[0].GetText()
	}
	if err := stream.Send(&pb.StreamResponse{
		Payload: &pb.StreamResponse_StatusUpdate{
			StatusUpdate: &pb.TaskStatusUpdateEvent{
				TaskId:    "up_grpc_stream_task",
				ContextId: "ctx_grpc_stream",
				Status: &pb.TaskStatus{
					State:     pb.TaskState_TASK_STATE_WORKING,
					Timestamp: timestamppb.Now(),
				},
			},
		},
	}); err != nil {
		return err
	}
	if err := stream.Send(&pb.StreamResponse{
		Payload: &pb.StreamResponse_ArtifactUpdate{
			ArtifactUpdate: &pb.TaskArtifactUpdateEvent{
				TaskId:    "up_grpc_stream_task",
				ContextId: "ctx_grpc_stream",
				Artifact: &pb.Artifact{
					ArtifactId: "art_grpc_01",
					Name:       "grpc-stream-output",
					Parts: []*pb.Part{
						{Content: &pb.Part_Text{Text: "streamed gRPC payload for " + txt}},
					},
				},
			},
		},
	}); err != nil {
		return err
	}
	return stream.Send(&pb.StreamResponse{
		Payload: &pb.StreamResponse_StatusUpdate{
			StatusUpdate: &pb.TaskStatusUpdateEvent{
				TaskId:    "up_grpc_stream_task",
				ContextId: "ctx_grpc_stream",
				Status: &pb.TaskStatus{
					State:     pb.TaskState_TASK_STATE_COMPLETED,
					Timestamp: timestamppb.Now(),
				},
			},
		},
	})
}

func (m *mockUpstreamGRPCAgent) CancelTask(ctx context.Context, req *pb.CancelTaskRequest) (*pb.Task, error) {
	m.recordMD(ctx)
	m.mu.Lock()
	m.canceledTaskID = req.GetId()
	m.mu.Unlock()
	if req.GetId() == "" {
		return nil, status.Error(codes.InvalidArgument, "missing id")
	}
	return &pb.Task{
		Id: req.GetId(),
		Status: &pb.TaskStatus{
			State:     pb.TaskState_TASK_STATE_CANCELED,
			Timestamp: timestamppb.Now(),
		},
	}, nil
}

func (m *mockUpstreamGRPCAgent) DeleteTaskPushNotificationConfig(_ context.Context, _ *pb.DeleteTaskPushNotificationConfigRequest) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}

// P1.1: Outbound JSONRPC and GRPC Upstream Agent Protocol Binding Tests
func TestA2A_OutboundJSONRPCAndGRPCUpstreamBindings(t *testing.T) {
	ctx := context.Background()
	repo := storage.NewMemoryRepository()
	vault, err := auth.NewVault("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	require.NoError(t, err)
	netPolicy, err := network.NewPolicy(config.OutboundSSRFConfig{
		AllowPrivateNetworks: true,
		AllowInsecureHTTP:    true,
	})
	require.NoError(t, err)

	signer := NewGatewayCardSigner("", "", nil, vault)
	verifier := NewUpstreamCardVerifier(nil, WithVerifierNetworkPolicy(netPolicy))
	router := NewRouterService(repo, vault, nil, netPolicy, nil, signer, verifier)

	// 1. Upstream JSON-RPC 2.0 server (sync + SSE stream + cancel)
	var jsonrpcCanceledID atomic.Value
	var jsonrpcLastAuth atomic.Value
	jsonrpcUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		jsonrpcLastAuth.Store(r.Header.Get("Authorization"))
		body, _ := io.ReadAll(r.Body)
		var rpcReq struct {
			JSONRPC string          `json:"jsonrpc"`
			ID      any             `json:"id"`
			Method  string          `json:"method"`
			Params  json.RawMessage `json:"params"`
		}
		require.NoError(t, json.Unmarshal(body, &rpcReq))
		switch rpcReq.Method {
		case string(a2aspec.SendMessage):
			w.Header().Set("Content-Type", MediaTypeA2AJSON)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"jsonrpc": "2.0",
				"id":      rpcReq.ID,
				"result": map[string]any{
					"task": map[string]any{
						"id":        "up_jsonrpc_task_99",
						"contextId": "ctx_jsonrpc_01",
						"status": map[string]any{
							"state": "TASK_STATE_WORKING",
							"message": map[string]any{
								"messageId": "msg_jsonrpc_01",
								"role":      "ROLE_AGENT",
								"parts":     []map[string]any{{"text": "JSON-RPC 2.0 upstream working"}},
							},
						},
					},
				},
			})
		case string(a2aspec.SendStreamingMessage):
			w.Header().Set("Content-Type", MediaTypeSSE)
			flusher, _ := w.(http.Flusher)
			frame1, _ := json.Marshal(map[string]any{
				"jsonrpc": "2.0",
				"id":      rpcReq.ID,
				"result": map[string]any{
					"statusUpdate": map[string]any{
						"taskId":    "up_jsonrpc_stream_01",
						"contextId": "ctx_jsonrpc_stream",
						"status":    map[string]any{"state": "TASK_STATE_WORKING"},
					},
				},
			})
			_, _ = fmt.Fprintf(w, "data: %s\n\n", frame1)
			if flusher != nil {
				flusher.Flush()
			}
			frame2, _ := json.Marshal(map[string]any{
				"jsonrpc": "2.0",
				"id":      rpcReq.ID,
				"result": map[string]any{
					"statusUpdate": map[string]any{
						"taskId":    "up_jsonrpc_stream_01",
						"contextId": "ctx_jsonrpc_stream",
						"status":    map[string]any{"state": "TASK_STATE_COMPLETED"},
					},
				},
			})
			_, _ = fmt.Fprintf(w, "data: %s\n\n", frame2)
			if flusher != nil {
				flusher.Flush()
			}
		case string(a2aspec.CancelTask):
			var p map[string]string
			_ = json.Unmarshal(rpcReq.Params, &p)
			jsonrpcCanceledID.Store(p["id"])
			w.Header().Set("Content-Type", MediaTypeA2AJSON)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"jsonrpc": "2.0",
				"id":      rpcReq.ID,
				"result":  map[string]any{"id": p["id"]},
			})
		}
	}))
	defer jsonrpcUpstream.Close()

	encSecret, encDEK, err := vault.EncryptString("jsonrpc-secret-token")
	require.NoError(t, err)
	require.NoError(t, repo.CreateA2AAgent(ctx, &domain.A2AAgent{
		ID:                  "ag_jsonrpc",
		OrgID:               "org_p1",
		Slug:                "jsonrpc-upstream-agent",
		Name:                "JSON-RPC Upstream Agent",
		EndpointURL:         jsonrpcUpstream.URL,
		ProtocolBinding:     domain.A2AProtocolBindingJSONRPC,
		AuthType:            "static",
		EncryptedAuthSecret: encSecret,
		EncryptedAuthDEK:    encDEK,
		IsActive:            true,
	}))

	idCtx := &domain.IdentityContext{
		OrgID:        "org_p1",
		TeamID:       "team_p1",
		UserID:       "user_p1",
		VirtualKeyID: "vk_p1",
	}

	// Test JSONRPC sync SendMessage + CancelTask
	syncResp, err := router.SendMessage(ctx, idCtx, "jsonrpc-upstream-agent", &a2aspec.SendMessageRequest{
		Message: a2aspec.Message{
			MessageId: "msg_u1",
			Role:      a2aspec.ROLEUSER,
			Parts:     []a2aspec.Part{a2aspec.NewTextPart("ping jsonrpc")},
		},
	})
	require.NoError(t, err)
	require.NotNil(t, syncResp.Task)
	assert.Equal(t, "Bearer jsonrpc-secret-token", jsonrpcLastAuth.Load())

	canceledTask, err := router.CancelTask(ctx, idCtx, "jsonrpc-upstream-agent", syncResp.Task.Id)
	require.NoError(t, err)
	assert.Equal(t, a2aspec.TASKSTATECANCELED, canceledTask.Status.State)
	assert.Equal(t, "up_jsonrpc_task_99", jsonrpcCanceledID.Load())

	// Test JSONRPC streaming SendStreamingMessage
	var jsonrpcFrames int
	err = router.SendStreamingMessage(ctx, idCtx, "jsonrpc-upstream-agent", &a2aspec.SendMessageRequest{
		Message: a2aspec.Message{
			MessageId: "msg_u2",
			Role:      a2aspec.ROLEUSER,
			Parts:     []a2aspec.Part{a2aspec.NewTextPart("stream jsonrpc")},
		},
	}, func(frame *a2aspec.StreamResponse, seq int64) error {
		jsonrpcFrames++
		return nil
	})
	require.NoError(t, err)
	assert.Equal(t, 2, jsonrpcFrames)

	// 2. Upstream gRPC server (sync + server-stream + cancel + metadata & W3C trace propagation)
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	grpcSrv := grpc.NewServer()
	mockGRPC := &mockUpstreamGRPCAgent{}
	pb.RegisterA2AServiceServer(grpcSrv, mockGRPC)
	go func() {
		_ = grpcSrv.Serve(lis)
	}()
	defer grpcSrv.Stop()

	grpcCardJSON := `{"name":"gRPC Upstream Agent","description":"gRPC A2A Agent","version":"1.0.0","supportedInterfaces":[{"protocolBinding":"GRPC","protocolVersion":"1.0","url":"grpc://` + lis.Addr().String() + `"}],"capabilities":{"extensions":[{"uri":"https://a2a.example.com/ext/audit-v1"}]},"defaultInputModes":["text/plain"],"defaultOutputModes":["text/plain"],"skills":[{"id":"s1","name":"s1","description":"d1","tags":["t1"]}]}`
	require.NoError(t, repo.CreateA2AAgent(ctx, &domain.A2AAgent{
		ID:              "ag_grpc",
		OrgID:           "org_p1",
		Slug:            "grpc-upstream-agent",
		Name:            "gRPC Upstream Agent",
		EndpointURL:     "grpc://" + lis.Addr().String(),
		AgentCardJSON:   grpcCardJSON,
		ProtocolBinding: domain.A2AProtocolBindingGRPC,
		AuthType:        "vault_jwt",
		IsActive:        true,
	}))

	tracedCtx := ContextWithCallOptions(ctx, CallOptions{
		Version:    "1.0",
		Extensions: []string{"https://a2a.example.com/ext/audit-v1"},
	})
	grpcSyncResp, err := router.SendMessage(tracedCtx, idCtx, "grpc-upstream-agent", &a2aspec.SendMessageRequest{
		Message: a2aspec.Message{
			MessageId: "msg_g1",
			Role:      a2aspec.ROLEUSER,
			Parts:     []a2aspec.Part{a2aspec.NewTextPart("hello grpc")},
		},
	})
	require.NoError(t, err)
	require.NotNil(t, grpcSyncResp.Task)
	require.NotNil(t, grpcSyncResp.Task.Status.Message)
	gotText, ok := a2aspec.PartText(grpcSyncResp.Task.Status.Message.Parts[0])
	require.True(t, ok)
	assert.Equal(t, "gRPC upstream echo: hello grpc", gotText)

	mockGRPC.mu.Lock()
	md := mockGRPC.lastMD
	mockGRPC.mu.Unlock()
	require.NotEmpty(t, md.Get("authorization"))
	assert.True(t, strings.HasPrefix(md.Get("authorization")[0], "Bearer "))
	assert.Equal(t, []string{"1.0"}, md.Get("a2a-version"))
	assert.Equal(t, []string{"https://a2a.example.com/ext/audit-v1"}, md.Get("a2a-extensions"))

	// Cancel active gRPC task and confirm CancelTask RPC reached upstream gRPC server
	canceledGRPC, err := router.CancelTask(ctx, idCtx, "grpc-upstream-agent", grpcSyncResp.Task.Id)
	require.NoError(t, err)
	assert.Equal(t, a2aspec.TASKSTATECANCELED, canceledGRPC.Status.State)
	mockGRPC.mu.Lock()
	assert.Equal(t, "up_grpc_task_01", mockGRPC.canceledTaskID)
	mockGRPC.mu.Unlock()

	// Stream from gRPC upstream agent
	var grpcStreamFrames []*a2aspec.StreamResponse
	err = router.SendStreamingMessage(ctx, idCtx, "grpc-upstream-agent", &a2aspec.SendMessageRequest{
		Message: a2aspec.Message{
			MessageId: "msg_g2",
			Role:      a2aspec.ROLEUSER,
			Parts:     []a2aspec.Part{a2aspec.NewTextPart("stream over grpc")},
		},
	}, func(frame *a2aspec.StreamResponse, seq int64) error {
		grpcStreamFrames = append(grpcStreamFrames, frame)
		return nil
	})
	require.NoError(t, err)
	require.Len(t, grpcStreamFrames, 3)
	require.NotNil(t, grpcStreamFrames[1].ArtifactUpdate)
	artTxt, ok := a2aspec.PartText(grpcStreamFrames[1].ArtifactUpdate.Artifact.Parts[0])
	require.True(t, ok)
	assert.Equal(t, "streamed gRPC payload for stream over grpc", artTxt)

	// Verify binding counters on RouterService.Metrics()
	rm := router.Metrics()
	assert.Equal(t, int64(4), rm.TasksDispatchedTotal)
	assert.Equal(t, int64(2), rm.UpstreamJSONRPCTotal)
	assert.Equal(t, int64(2), rm.UpstreamGRPCTotal)
	assert.Equal(t, int64(2), rm.TasksCanceledTotal)
}

// P1.2: Third-Party A2A v1.0 SDK Wire Interop (Multi-modal Parts, Extensions, & Automatic JWKS Key Rotation)
func TestA2A_ThirdPartySDKWireInteropAndJWKSAutoRefresh(t *testing.T) {
	ctx := context.Background()

	// 1. Multi-modal Part union decode & roundtrip (text + raw bytes + url + structured data + metadata)
	sdkPayload := []byte(`{
		"message": {
			"messageId": "msg_sdk_multimodal_01",
			"role": "ROLE_USER",
			"parts": [
				{
					"text": "Analyze the attached PDF and JSON telemetry.",
					"metadata": {"lang": "en-US"}
				},
				{
					"raw": "JVBERi0xLjQK",
					"filename": "report.pdf",
					"mediaType": "application/pdf"
				},
				{
					"url": "https://storage.example.com/datasets/q3.parquet",
					"mediaType": "application/vnd.apache.parquet"
				},
				{
					"data": {
						"region": "eu-west-1",
						"thresholds": [0.95, 0.99],
						"strict": true
					},
					"metadata": {"schema": "v1"}
				}
			]
		}
	}`)
	req, err := a2aspec.DecodeStrict[a2aspec.SendMessageRequest]("SendMessageRequest", sdkPayload)
	require.NoError(t, err)
	require.Len(t, req.Message.Parts, 4)

	// Verify round-trip through protojson (gRPC specToPB -> pbToSpec) preserves every union variant
	pbReq, err := specToPB[pb.SendMessageRequest](req)
	require.NoError(t, err)
	roundTripReq, err := pbToSpec[a2aspec.SendMessageRequest](pbReq)
	require.NoError(t, err)
	rtJSON, err := json.Marshal(roundTripReq)
	require.NoError(t, err)
	_, err = a2aspec.DecodeStrict[a2aspec.SendMessageRequest]("SendMessageRequest", rtJSON)
	require.NoError(t, err)
	require.Len(t, roundTripReq.Message.Parts, 4)

	// 2. Automatic JWKS key rotation refresh on unknown kid with rate-limiting cooldown
	key1, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	key2, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	var serveRotatedKey atomic.Bool
	var jwksFetchCount atomic.Int32
	jwksSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		jwksFetchCount.Add(1)
		activeKey := key1
		activeKid := "kid-gen-1"
		if serveRotatedKey.Load() {
			activeKey = key2
			activeKid = "kid-gen-2"
		}
		byteLen := (elliptic.P256().Params().BitSize + 7) / 8
		xb := make([]byte, byteLen)
		yb := make([]byte, byteLen)
		activeKey.PublicKey.X.FillBytes(xb)
		activeKey.PublicKey.Y.FillBytes(yb)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]any{
				{
					"kty": "EC",
					"crv": "P-256",
					"kid": activeKid,
					"x":   base64.RawURLEncoding.EncodeToString(xb),
					"y":   base64.RawURLEncoding.EncodeToString(yb),
				},
			},
		})
	}))
	defer jwksSrv.Close()

	netPolicy, err := network.NewPolicy(config.OutboundSSRFConfig{
		AllowPrivateNetworks: true,
		AllowInsecureHTTP:    true,
	})
	require.NoError(t, err)

	verifier := NewUpstreamCardVerifier(
		nil,
		WithVerifierNetworkPolicy(netPolicy),
		WithVerifierTrustedJWKS(map[string]string{"rotating-agent": jwksSrv.URL}),
		WithVerifierRefreshCooldown(0), // allow immediate auto-refresh on rotation
	)

	// Initial JWKS load learns kid-gen-1
	require.NoError(t, verifier.LoadJWKS(ctx, jwksSrv.URL))
	assert.Equal(t, int32(1), jwksFetchCount.Load())

	// Rotate upstream key to kid-gen-2 and sign an AgentCard with kid-gen-2
	serveRotatedKey.Store(true)
	card := &a2aspec.AgentCard{
		Name:        "Rotating Key Agent",
		Description: "Tests automatic JWKS refresh on unknown kid",
		Version:     "1.0.0",
		SupportedInterfaces: []a2aspec.AgentInterface{
			{ProtocolBinding: "HTTP+JSON", ProtocolVersion: "1.0", Url: "https://agent.example.com/a2a/v1"},
		},
		DefaultInputModes:  []string{"text/plain"},
		DefaultOutputModes: []string{"text/plain"},
		Capabilities:       a2aspec.AgentCapabilities{},
		Skills:             []a2aspec.AgentSkill{{Id: "s1", Name: "Skill 1", Description: "Desc", Tags: []string{"t1"}}},
	}

	rawCardBytes, err := json.Marshal(card)
	require.NoError(t, err)
	var cardMap map[string]any
	require.NoError(t, json.Unmarshal(rawCardBytes, &cardMap))
	delete(cardMap, "signatures")
	jcsBytes, err := CanonicalizeJCS(cardMap)
	require.NoError(t, err)

	protectedB64 := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256","kid":"kid-gen-2"}`))
	payloadB64 := base64.RawURLEncoding.EncodeToString(jcsBytes)
	digest := sha256.Sum256([]byte(protectedB64 + "." + payloadB64))
	rVal, sVal, err := ecdsa.Sign(rand.Reader, key2, digest[:])
	require.NoError(t, err)
	rawSig := make([]byte, 64)
	rVal.FillBytes(rawSig[:32])
	sVal.FillBytes(rawSig[32:])
	sigs := []a2aspec.AgentCardSignature{
		{
			Protected: protectedB64,
			Signature: base64.RawURLEncoding.EncodeToString(rawSig),
		},
	}
	card.Signatures = &sigs

	// VerifyCardSignatures encounters unknown kid-gen-2, auto-refreshes JWKS, and succeeds!
	require.NoError(t, verifier.VerifyCardSignatures(card))
	assert.Equal(t, int32(2), jwksFetchCount.Load())
}

// P2.1: Mid-Stream Fault Injection, Outbox Trace Propagation, and Retention Pruning Chaos Tests
func TestA2A_MidStreamFaultInjectionAndLeaseRecoveryChaos(t *testing.T) {
	ctx := context.Background()
	repo := storage.NewMemoryRepository()
	vault, err := auth.NewVault("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	require.NoError(t, err)
	netPolicy, err := network.NewPolicy(config.OutboundSSRFConfig{
		AllowPrivateNetworks: true,
		AllowInsecureHTTP:    true,
	})
	require.NoError(t, err)

	signer := NewGatewayCardSigner("", "", nil, vault)
	verifier := NewUpstreamCardVerifier(nil, WithVerifierNetworkPolicy(netPolicy))
	router := NewRouterService(repo, vault, nil, netPolicy, nil, signer, verifier)

	// 1. Upstream agent that drops TCP connection mid-SSE stream after emitting 1 frame
	abruptServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", MediaTypeSSE)
		flusher, _ := w.(http.Flusher)
		_, _ = fmt.Fprintf(w, "data: {\"statusUpdate\":{\"taskId\":\"up_drop\",\"contextId\":\"ctx_drop\",\"status\":{\"state\":\"TASK_STATE_WORKING\"}}}\n\n")
		if flusher != nil {
			flusher.Flush()
		}
		// Write malformed incomplete frame and close abruptly
		_, _ = fmt.Fprintf(w, "data: {\"statusUpdate\":{\"taskId\":\n\n")
		if flusher != nil {
			flusher.Flush()
		}
	}))
	defer abruptServer.Close()

	require.NoError(t, repo.CreateA2AAgent(ctx, &domain.A2AAgent{
		ID:              "ag_chaos",
		OrgID:           "org_chaos",
		Slug:            "chaos-drop-agent",
		Name:            "Chaos Drop Agent",
		EndpointURL:     abruptServer.URL,
		ProtocolBinding: domain.A2AProtocolBindingHTTPJSON,
		IsActive:        true,
	}))

	idCtx := &domain.IdentityContext{
		OrgID:        "org_chaos",
		TeamID:       "team_chaos",
		UserID:       "user_chaos",
		VirtualKeyID: "vk_chaos",
	}

	err = router.SendStreamingMessage(ctx, idCtx, "chaos-drop-agent", &a2aspec.SendMessageRequest{
		Message: a2aspec.Message{
			MessageId: "msg_chaos_1",
			Role:      a2aspec.ROLEUSER,
			Parts:     []a2aspec.Part{a2aspec.NewTextPart("trigger stream drop")},
		},
	}, nil)
	require.Error(t, err, "broken mid-stream SSE frame must return an error")

	// Verify task transitioned deterministically to TASK_STATE_FAILED (never orphaned in WORKING)
	tasks, total, err := repo.ListA2ATasks(ctx, domain.A2ATaskListFilter{OrgID: "org_chaos"})
	require.NoError(t, err)
	require.Equal(t, 1, total)
	assert.Equal(t, domain.A2ATaskStateFailed, tasks[0].State)

	// 2. Outbox webhook W3C traceparent propagation + TTL retention pruning
	var receivedTraceparent atomic.Value
	var receivedIdempotencyKey atomic.Value
	webhookSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedTraceparent.Store(r.Header.Get("Traceparent"))
		receivedIdempotencyKey.Store(r.Header.Get("Idempotency-Key"))
		w.WriteHeader(http.StatusOK)
	}))
	defer webhookSrv.Close()

	require.NoError(t, repo.SetA2APushNotificationConfig(ctx, &domain.A2APushNotificationConfig{
		ID:        "push_chaos_1",
		TaskID:    tasks[0].ID,
		TargetURL: webhookSrv.URL,
	}))
	_, err = repo.AppendA2ATaskEvent(ctx, tasks[0].ID, "status", `{"statusUpdate":{"taskId":"`+tasks[0].ID+`","contextId":"ctx_drop","status":{"state":"TASK_STATE_FAILED"}}}`)
	require.NoError(t, err)

	// Mark stream publications as published
	pubs, err := repo.ClaimPendingA2AStreamPublications(ctx, 50)
	require.NoError(t, err)
	for _, p := range pubs {
		require.NoError(t, repo.MarkA2AStreamPublicationSuccess(ctx, p.ID))
	}

	outboxWorker := NewOutboxWorker(repo, vault, netPolicy, 3, 50*time.Millisecond)
	spanCtx := observability.WithTraceContext(ctx, observability.TraceContext{
		TraceID:     "4bf92f3577b34da6a3ce929d0e0e4736",
		SpanID:      "00f067aa0ba902b7",
		TraceParent: "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
	})
	outboxWorker.ProcessPendingEvents(spanCtx)

	tp, _ := receivedTraceparent.Load().(string)
	assert.True(t, strings.HasPrefix(tp, "00-"), "outbox webhook must propagate W3C traceparent header, got %q", tp)
	assert.NotEmpty(t, receivedIdempotencyKey.Load())

	// Configure aggressive TTL and prune expired publications, outbox events, and terminal tasks
	outboxWorker.SetRetentionPolicy(1*time.Millisecond, 1*time.Millisecond, 1*time.Millisecond)
	pruned, err := outboxWorker.PruneExpired(ctx, time.Now().UTC().Add(10*time.Second))
	require.NoError(t, err)
	assert.GreaterOrEqual(t, pruned, int64(3), "expected published stream pubs, delivered outbox event, and terminal task to be pruned")

	delivered, deadLetter, prunedMetric := outboxWorker.Metrics()
	assert.Equal(t, int64(1), delivered)
	assert.Equal(t, int64(0), deadLetter)
	assert.Equal(t, pruned, prunedMetric)
}

// P2.2: 500-Client Slow-Consumer SSE Fan-Out Backpressure & ActiveSubscribers Metric Benchmark
func TestA2A_SlowConsumer500SubscribersBackpressure(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	repo := storage.NewMemoryRepository()
	require.NoError(t, repo.CreateA2AAgent(ctx, &domain.A2AAgent{
		ID:                 "ag_fanout",
		OrgID:              "org_fanout",
		Slug:               "fanout-agent",
		Name:               "Fanout Agent",
		EndpointURL:        "http://127.0.0.1:65535",
		ProtocolBinding:    domain.A2AProtocolBindingHTTPJSON,
		TaskVisibilityMode: domain.TaskVisibilityTeam,
		IsActive:           true,
	}))

	now := time.Now().UTC()
	task := &domain.A2ATask{
		ID:           "task_fanout_500",
		AgentID:      "ag_fanout",
		OrgID:        "org_fanout",
		TeamID:       "team_fanout",
		VirtualKeyID: "vk_fanout",
		UserID:       "user_fanout",
		ContextID:    "ctx_fanout",
		State:        domain.A2ATaskStateWorking,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	require.NoError(t, repo.CreateA2ATask(ctx, task))
	_, err := repo.AppendA2ATaskEvent(ctx, task.ID, "status", `{"statusUpdate":{"taskId":"task_fanout_500","contextId":"ctx_fanout","status":{"state":"TASK_STATE_WORKING"}}}`)
	require.NoError(t, err)

	sub := NewStreamSubscriber(repo, nil, nil, 64)
	idCtx := &domain.IdentityContext{
		OrgID:        "org_fanout",
		TeamID:       "team_fanout",
		UserID:       "user_fanout",
		VirtualKeyID: "vk_fanout",
	}

	const numSubscribers = 500
	channels := make([]<-chan StreamEnvelope, numSubscribers)
	for i := 0; i < numSubscribers; i++ {
		ch, sErr := sub.SubscribeChannel(ctx, idCtx, "fanout-agent", task.ID, 0)
		require.NoError(t, sErr)
		channels[i] = ch
	}

	assert.Equal(t, int64(numSubscribers), sub.ActiveSubscribers())

	// Emit terminal event so all 500 subscribers receive both events and exit cleanly
	task.State = domain.A2ATaskStateCompleted
	task.CompletedAt = &now
	require.NoError(t, repo.UpdateA2ATask(ctx, task, 100))
	_, err = repo.AppendA2ATaskEvent(ctx, task.ID, "status", `{"statusUpdate":{"taskId":"task_fanout_500","contextId":"ctx_fanout","status":{"state":"TASK_STATE_COMPLETED"}}}`)
	require.NoError(t, err)

	var wg sync.WaitGroup
	var completedSubscribers atomic.Int64
	for i := 0; i < numSubscribers; i++ {
		wg.Add(1)
		go func(idx int, ch <-chan StreamEnvelope) {
			defer wg.Done()
			// First 25 subscribers simulate slow consumers
			if idx < 25 {
				time.Sleep(15 * time.Millisecond)
			}
			count := 0
			for range ch {
				count++
			}
			if count >= 2 {
				completedSubscribers.Add(1)
			}
		}(i, channels[i])
	}
	wg.Wait()

	assert.Equal(t, int64(numSubscribers), completedSubscribers.Load())
	assert.Equal(t, int64(0), sub.ActiveSubscribers(), "all 500 subscriber goroutines must exit and decrement activeSubscribers to 0")
}

// P3.1: Native Go Fuzz Target for RFC 8785 JCS Canonicalizer
func FuzzCanonicalizeJCS(f *testing.F) {
	f.Add([]byte(`{"b":1,"a":"hello","nested":{"z":true,"y":[3,2,1]}}`))
	f.Add([]byte(`{"unicode":"\u0000\u001f\u2028","numbers":[0,-0.0,1e20,1e-7]}`))
	f.Add([]byte(`[]`))
	f.Fuzz(func(t *testing.T, data []byte) {
		var v any
		if err := json.Unmarshal(data, &v); err != nil {
			return
		}
		out1, err := CanonicalizeJCS(v)
		if err != nil {
			return
		}
		// Canonical output must be valid JSON and idempotent upon re-canonicalization
		var v2 any
		require.NoError(t, json.Unmarshal(out1, &v2))
		out2, err := CanonicalizeJCS(v2)
		require.NoError(t, err)
		assert.Equal(t, out1, out2)
	})
}

// P3.2: Native Go Fuzz Target for AgentCard Detached JWS Verifier
func FuzzVerifyDetachedJWS(f *testing.F) {
	f.Add("eyJhbGciOiJFUzI1NiIsImtpZCI6ImstMSJ9", "", "AAAA")
	f.Add("not-base64!", "payload", "sig")
	f.Add(base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","kid":"unknown"}`)), "", "c2ln")

	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	verifier := NewUpstreamCardVerifier(map[string]any{
		"k-1": &priv.PublicKey,
	})
	sampleCard := &a2aspec.AgentCard{
		Name:        "Fuzz Card",
		Description: "Fuzzing JWS verifier",
		Version:     "1.0.0",
		SupportedInterfaces: []a2aspec.AgentInterface{
			{ProtocolBinding: "HTTP+JSON", ProtocolVersion: "1.0", Url: "https://example.com/a2a"},
		},
		DefaultInputModes:  []string{"text/plain"},
		DefaultOutputModes: []string{"text/plain"},
		Capabilities:       a2aspec.AgentCapabilities{},
		Skills:             []a2aspec.AgentSkill{{Id: "s1", Name: "S1", Description: "D1", Tags: []string{"t1"}}},
	}

	f.Fuzz(func(t *testing.T, protectedB64, payloadB64, sigB64 string) {
		_ = verifier.verifyDetachedJWS(sampleCard, protectedB64, payloadB64, sigB64)
	})
}

// P3.3: Native Go Fuzz Target for Strict OpenAPI Schema & Union Decoder
func FuzzDecodeStrictOpenAPI(f *testing.F) {
	f.Add([]byte(`{"message":{"messageId":"m1","role":"ROLE_USER","parts":[{"text":"hi"}]}}`))
	f.Add([]byte(`{"statusUpdate":{"taskId":"t1","contextId":"c1","status":{"state":"TASK_STATE_WORKING"}}}`))
	f.Add([]byte(`{"task":{"id":"t1","status":{"state":"TASK_STATE_COMPLETED"}},"message":{"messageId":"m1","role":"ROLE_AGENT","parts":[{"text":"conflict"}]}}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = a2aspec.DecodeStrict[a2aspec.SendMessageRequest]("SendMessageRequest", data)
		_, _ = a2aspec.DecodeStrict[a2aspec.SendMessageResponse]("SendMessageResponse", data)
		_, _ = a2aspec.DecodeStrict[a2aspec.StreamResponse]("StreamResponse", data)
		_, _ = a2aspec.DecodeStrict[a2aspec.AgentCard]("AgentCard", data)
	})
}
