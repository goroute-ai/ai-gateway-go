package a2a

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/a2a/pb"
	"github.com/goroute-ai/ai-gateway-go/internal/auth"
	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/security/network"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"
)

// 1. Strict ProtoJSON Unknown-Field Rejection Tests
func TestStrictProtoJSONRejection(t *testing.T) {
	// Valid message payload
	validJSON := []byte(`{
		"messageId": "msg_001",
		"role": "ROLE_USER",
		"parts": [
			{"text": "Hello Agent"}
		]
	}`)
	var msg pb.Message
	err := ParseStrictProtoJSON(validJSON, &msg)
	require.NoError(t, err)
	assert.Equal(t, "msg_001", msg.MessageId)

	// Injected unknown field (e.g. proto tampering attempt)
	unknownFieldJSON := []byte(`{
		"messageId": "msg_002",
		"role": "ROLE_USER",
		"parts": [
			{"text": "Hello Agent"}
		],
		"injectedField": "malicious_payload"
	}`)
	var msg2 pb.Message
	err = ParseStrictProtoJSON(unknownFieldJSON, &msg2)
	require.Error(t, err, "Strict protojson MUST reject unknown fields")
	assert.Contains(t, err.Error(), "unknown field")
}

// 2. RFC 8785 JCS Canonicalization and AgentCard JWS Signing & Verification Tests
func TestAgentCardJCSSigningAndVerification(t *testing.T) {
	// Generate upstream ECDSA key pair
	upstreamPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	upstreamKid := "upstream-agent-key-1"

	// Setup verifier with trusted upstream key
	verifier := NewUpstreamCardVerifier(map[string]any{
		upstreamKid: &upstreamPriv.PublicKey,
	})

	card := &pb.AgentCard{
		Name:        "Financial Auditor Agent",
		Description: "Automated SEC compliance auditor",
		Version:     "1.0.0",
		SupportedInterfaces: []*pb.AgentInterface{
			{
				ProtocolBinding: "HTTP+JSON",
				Url:             "https://upstream.agent.internal/a2a",
			},
		},
	}

	// 1. Sign original card using upstream key
	signerUpstream := NewGatewayCardSigner(upstreamKid, "ES256", upstreamPriv, nil)
	signedUpstreamCard, jwsStr, err := signerUpstream.RewriteAndSignAgentCard(card, "https://upstream.agent.internal", "fin-auditor")
	require.NoError(t, err)
	require.NotEmpty(t, jwsStr)

	// 2. Verifier validates upstream card signature -> Success
	err = verifier.VerifyAgentCard(signedUpstreamCard, jwsStr)
	require.NoError(t, err)

	// 3. Tamper with card -> Verification fails
	tamperedCard := &pb.AgentCard{
		Name:        "Financial Auditor Agent",
		Description: "TAMPERED: Malicious prompt injected into description",
		Version:     "1.0.0",
	}
	err = verifier.VerifyAgentCard(tamperedCard, jwsStr)
	require.Error(t, err, "Verification must fail on tampered agent card")

	// 4. Gateway re-writes and signs card with Gateway key
	gwPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	gwKid := "gw-master-signer-v1"
	gwSigner := NewGatewayCardSigner(gwKid, "ES256", gwPriv, nil)

	gwSignedCard, gwJWS, err := gwSigner.RewriteAndSignAgentCard(card, "https://gateway.example.com", "fin-auditor")
	require.NoError(t, err)
	require.NotEmpty(t, gwJWS)

	// Ensure interface was rewritten to point to Gateway namespace
	require.NotEmpty(t, gwSignedCard.SupportedInterfaces)
	assert.Equal(t, "https://gateway.example.com/a2a/v1/agents/fin-auditor", gwSignedCard.SupportedInterfaces[0].Url)

	// Verify gateway signature
	gwVerifier := NewUpstreamCardVerifier(map[string]any{
		gwKid: &gwPriv.PublicKey,
	})
	assert.NoError(t, gwVerifier.VerifyAgentCard(gwSignedCard, gwJWS))
}

// 3. Task State Machine Transition Tests
func TestTaskStateMachineTransitions(t *testing.T) {
	// Legal transitions
	assert.NoError(t, ValidateStateTransition(pb.TaskState_TASK_STATE_SUBMITTED, pb.TaskState_TASK_STATE_WORKING))
	assert.NoError(t, ValidateStateTransition(pb.TaskState_TASK_STATE_WORKING, pb.TaskState_TASK_STATE_INPUT_REQUIRED))
	assert.NoError(t, ValidateStateTransition(pb.TaskState_TASK_STATE_INPUT_REQUIRED, pb.TaskState_TASK_STATE_WORKING))
	assert.NoError(t, ValidateStateTransition(pb.TaskState_TASK_STATE_WORKING, pb.TaskState_TASK_STATE_COMPLETED))
	assert.NoError(t, ValidateStateTransition(pb.TaskState_TASK_STATE_WORKING, pb.TaskState_TASK_STATE_FAILED))
	assert.NoError(t, ValidateStateTransition(pb.TaskState_TASK_STATE_WORKING, pb.TaskState_TASK_STATE_CANCELED))
	assert.NoError(t, ValidateStateTransition(pb.TaskState_TASK_STATE_SUBMITTED, pb.TaskState_TASK_STATE_CANCELED))

	// Identity transition (no-op)
	assert.NoError(t, ValidateStateTransition(pb.TaskState_TASK_STATE_WORKING, pb.TaskState_TASK_STATE_WORKING))
	assert.NoError(t, ValidateStateTransition(pb.TaskState_TASK_STATE_COMPLETED, pb.TaskState_TASK_STATE_COMPLETED))

	// Illegal transitions from Terminal states
	err := ValidateStateTransition(pb.TaskState_TASK_STATE_COMPLETED, pb.TaskState_TASK_STATE_WORKING)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "terminal state")

	err = ValidateStateTransition(pb.TaskState_TASK_STATE_FAILED, pb.TaskState_TASK_STATE_WORKING)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "terminal state")

	err = ValidateStateTransition(pb.TaskState_TASK_STATE_CANCELED, pb.TaskState_TASK_STATE_WORKING)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "terminal state")
}

// 4. Task Visibility Isolation Tests
func TestTaskVisibilityIsolationModes(t *testing.T) {
	task := &domain.A2ATask{
		ID:           "task_sec_001",
		OrgID:        "org_finance",
		TeamID:       "team_quant",
		VirtualKeyID: "vk_key_1",
		UserID:       "user_alice",
	}

	callerOwner := &domain.IdentityContext{
		OrgID:        "org_finance",
		TeamID:       "team_quant",
		VirtualKeyID: "vk_key_1",
		UserID:       "user_alice",
	}

	callerDifferentKeySameUser := &domain.IdentityContext{
		OrgID:        "org_finance",
		TeamID:       "team_quant",
		VirtualKeyID: "vk_key_2",
		UserID:       "user_alice",
	}

	callerSameTeamDifferentUser := &domain.IdentityContext{
		OrgID:        "org_finance",
		TeamID:       "team_quant",
		VirtualKeyID: "vk_key_3",
		UserID:       "user_bob",
	}

	callerOtherOrg := &domain.IdentityContext{
		OrgID:        "org_competitor",
		TeamID:       "team_quant",
		VirtualKeyID: "vk_key_1",
		UserID:       "user_alice",
	}

	// 1. Cross-tenant is ALWAYS blocked regardless of mode
	assert.False(t, CheckTaskVisibility(task, callerOtherOrg, domain.TaskVisibilityOrgAdmin))
	assert.False(t, CheckTaskVisibility(task, callerOtherOrg, domain.TaskVisibilityKeyStrict))

	// 2. Mode: key_strict (default)
	assert.True(t, CheckTaskVisibility(task, callerOwner, domain.TaskVisibilityKeyStrict))
	assert.False(t, CheckTaskVisibility(task, callerDifferentKeySameUser, domain.TaskVisibilityKeyStrict))
	assert.False(t, CheckTaskVisibility(task, callerSameTeamDifferentUser, domain.TaskVisibilityKeyStrict))

	// 3. Mode: user_strict
	assert.True(t, CheckTaskVisibility(task, callerOwner, domain.TaskVisibilityUserStrict))
	assert.True(t, CheckTaskVisibility(task, callerDifferentKeySameUser, domain.TaskVisibilityUserStrict))
	assert.False(t, CheckTaskVisibility(task, callerSameTeamDifferentUser, domain.TaskVisibilityUserStrict))

	// 4. Mode: team
	assert.True(t, CheckTaskVisibility(task, callerOwner, domain.TaskVisibilityTeam))
	assert.True(t, CheckTaskVisibility(task, callerSameTeamDifferentUser, domain.TaskVisibilityTeam))

	// 5. Mode: org_admin
	assert.True(t, CheckTaskVisibility(task, callerSameTeamDifferentUser, domain.TaskVisibilityOrgAdmin))
}

// 5. End-to-End RouterService Operations: Monotonic Event Sequencing, Kill-Switch, Cancel
func TestRouterServiceOperations(t *testing.T) {
	ctx := context.Background()
	repo := storage.NewMemoryRepository()
	vault, err := auth.NewVault("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	require.NoError(t, err)
	rbac := auth.NewRBACEngine(repo)

	netPolicy, err := network.NewPolicy(config.OutboundSSRFConfig{
		AllowPrivateNetworks: true,
		AllowInsecureHTTP:    true,
	})
	require.NoError(t, err)

	// Mock upstream A2A agent
	mockUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req pb.SendMessageRequest
		bodyBytes, _ := json.Marshal(map[string]any{
			"message": map[string]any{
				"messageId": "msg_reply_1",
				"role":      "ROLE_AGENT",
				"parts": []map[string]any{
					{"text": "Acknowledged by upstream agent"},
				},
			},
		})
		_ = protojson.Unmarshal(bodyBytes, &req)

		respObj := &pb.SendMessageResponse{
			Payload: &pb.SendMessageResponse_Message{
				Message: req.Message,
			},
		}
		outJSON, _ := protojson.Marshal(respObj)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(outJSON)
	}))
	defer mockUpstream.Close()

	// Seed A2AAgent
	agent := &domain.A2AAgent{
		ID:                 "agent_1",
		OrgID:              "org_test",
		Name:               "Test Assistant Agent",
		Slug:               "test-agent",
		EndpointURL:        mockUpstream.URL,
		TaskVisibilityMode: domain.TaskVisibilityKeyStrict,
		IsActive:           true,
		IsKilled:           false,
		CreatedAt:          time.Now().UTC(),
		UpdatedAt:          time.Now().UTC(),
	}
	require.NoError(t, repo.CreateA2AAgent(ctx, agent))

	signer := NewGatewayCardSigner("kid1", "ES256", nil, vault)
	verifier := NewUpstreamCardVerifier(nil)
	routerSvc := NewRouterService(repo, vault, rbac, netPolicy, nil, signer, verifier)

	idCtx := &domain.IdentityContext{
		KeyPrefix:    "sk-gw-client",
		VirtualKeyID: "vk_caller_1",
		OrgID:        "org_test",
	}

	// 1. SendMessage -> Creates new task and records event seq = 1
	sendReq := &pb.SendMessageRequest{
		Message: &pb.Message{
			MessageId: "msg_client_001",
			Role:      pb.Role_ROLE_USER,
			Parts: []*pb.Part{
				{
					Content: &pb.Part_Text{Text: "Please analyze Q3 report"},
				},
			},
		},
	}

	resp, err := routerSvc.SendMessage(ctx, idCtx, "test-agent", sendReq)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.NotNil(t, resp.GetMessage())

	// Verify task was created with status completed
	tasks, err := repo.ListA2ATasks(ctx, agent.ID, idCtx.VirtualKeyID, 10)
	require.NoError(t, err)
	require.Len(t, tasks, 1)
	task := tasks[0]
	assert.Equal(t, domain.A2ATaskStateCompleted, task.State)
	assert.Equal(t, int64(1), task.LastEventSeq, "Event sequence must be monotonic starting at 1")

	// 2. GetTask
	protoTask, err := routerSvc.GetTask(ctx, idCtx, "test-agent", task.ID)
	require.NoError(t, err)
	require.NotNil(t, protoTask)
	assert.Equal(t, task.ID, protoTask.Id)

	// 3. CancelTask on completed task -> Must fail with CodeTaskAlreadyCompleted
	_, err = routerSvc.CancelTask(ctx, idCtx, "test-agent", task.ID)
	require.Error(t, err)
	var a2aErr *A2AError
	require.ErrorAs(t, err, &a2aErr)
	assert.Equal(t, CodeTaskAlreadyCompleted, a2aErr.Code)

	// 4. Emergency Kill-Switch test
	agent.IsKilled = true
	_ = repo.UpdateA2AAgent(ctx, agent)

	_, err = routerSvc.SendMessage(ctx, idCtx, "test-agent", sendReq)
	require.Error(t, err)
	require.ErrorAs(t, err, &a2aErr)
	assert.Equal(t, CodeAgentKilled, a2aErr.Code)
}
