package e2e_test

import (
	"bufio"
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

	"github.com/goroute-ai/ai-gateway-go/internal/a2a"
	"github.com/goroute-ai/ai-gateway-go/internal/a2a/pb"
	a2aspec "github.com/goroute-ai/ai-gateway-go/internal/a2a/spec"
	"github.com/goroute-ai/ai-gateway-go/internal/auth"
	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/pkg/gateway"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type liveE2EUpstreamGRPCAgent struct {
	pb.UnimplementedA2AServiceServer
}

func (u *liveE2EUpstreamGRPCAgent) SendMessage(_ context.Context, req *pb.SendMessageRequest) (*pb.SendMessageResponse, error) {
	txt := ""
	if len(req.GetMessage().GetParts()) > 0 {
		txt = req.GetMessage().GetParts()[0].GetText()
	}
	return &pb.SendMessageResponse{
		Payload: &pb.SendMessageResponse_Task{
			Task: &pb.Task{
				Id:        "live_up_grpc_task",
				ContextId: "live_ctx_grpc",
				Status: &pb.TaskStatus{
					State:     pb.TaskState_TASK_STATE_COMPLETED,
					Timestamp: timestamppb.Now(),
					Message: &pb.Message{
						MessageId: "live_grpc_msg_1",
						Role:      pb.Role_ROLE_AGENT,
						Parts: []*pb.Part{
							{Content: &pb.Part_Text{Text: "live gRPC response: " + txt}},
						},
					},
				},
			},
		},
	}, nil
}

func signCardES256JWS(t *testing.T, priv *ecdsa.PrivateKey, kid string, card *a2aspec.AgentCard) a2aspec.AgentCard {
	t.Helper()
	cp := *card
	cp.Signatures = nil
	canonical, err := a2a.CanonicalizeJCS(&cp)
	if err != nil {
		t.Fatalf("CanonicalizeJCS: %v", err)
	}
	hdrJSON, _ := json.Marshal(map[string]any{"alg": "ES256", "kid": kid, "typ": "JWT"})
	hdrB64 := base64.RawURLEncoding.EncodeToString(hdrJSON)
	payB64 := base64.RawURLEncoding.EncodeToString(canonical)
	digest := sha256.Sum256([]byte(hdrB64 + "." + payB64))
	r, s, err := ecdsa.Sign(rand.Reader, priv, digest[:])
	if err != nil {
		t.Fatalf("ecdsa.Sign: %v", err)
	}
	sig := make([]byte, 64)
	rBytes, sBytes := r.Bytes(), s.Bytes()
	copy(sig[32-len(rBytes):32], rBytes)
	copy(sig[64-len(sBytes):64], sBytes)
	cp.Signatures = &[]a2aspec.AgentCardSignature{
		{
			Protected: hdrB64,
			Signature: base64.RawURLEncoding.EncodeToString(sig),
		},
	}
	return cp
}

func ecdsaJWKSEntry(kid string, pub *ecdsa.PublicKey) map[string]any {
	xBytes := make([]byte, 32)
	yBytes := make([]byte, 32)
	xb, yb := pub.X.Bytes(), pub.Y.Bytes()
	copy(xBytes[32-len(xb):], xb)
	copy(yBytes[32-len(yb):], yb)
	return map[string]any{
		"kty": "EC",
		"crv": "P-256",
		"alg": "ES256",
		"use": "sig",
		"kid": kid,
		"x":   base64.RawURLEncoding.EncodeToString(xBytes),
		"y":   base64.RawURLEncoding.EncodeToString(yBytes),
	}
}

func doLiveHTTP(t *testing.T, method, url, authToken, contentType, body string, extraHeaders map[string]string) (int, http.Header, []byte) {
	t.Helper()
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, url, reader)
	if err != nil {
		t.Fatalf("new request %s %s: %v", method, url, err)
	}
	if authToken != "" {
		req.Header.Set("Authorization", "Bearer "+authToken)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	for k, v := range extraHeaders {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do request %s %s: %v", method, url, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body %s %s: %v", method, url, err)
	}
	return resp.StatusCode, resp.Header, raw
}

func TestLiveA2A_FullOpenAPIConformance_DualNode_GRPC_Security_And_SDK(t *testing.T) {
	cluster := setupConfigurableDualNodeCluster(t, func(cfg *config.Config) {
		cfg.A2A.Enabled = true
		cfg.A2A.EnableHTTPJSON = true
		cfg.A2A.EnableJSONRPC = true
		cfg.A2A.EnableSubscribePostCompat = true
		cfg.A2A.AllowLegacyCardDiscovery = true
		cfg.A2A.MaxPushRetries = 2
		cfg.A2A.StreamPublishInterval = 25 * time.Millisecond
		cfg.A2A.AllowedSigningAlgs = []string{"ES256", "RS256", "EdDSA"}
	})

	ctx := context.Background()
	runID := fmt.Sprintf("%d", time.Now().UnixNano())

	// 1. Reference Upstream A2A v1.0 Agent with real ES256 JWS Card + JWKS + SSE + Multi-Turn + Cancel
	upstreamKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate upstream ECDSA key: %v", err)
	}
	const upstreamKID = "upstream-live-es256-k1"
	const expectedUpstreamSecret = "upstream-vault-secret-live-1"
	var upstreamSecretHits atomic.Int32
	var upstreamSeq atomic.Int64
	var upstreamURL string

	refUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/.well-known/jwks.json":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"keys": []any{ecdsaJWKSEntry(upstreamKID, &upstreamKey.PublicKey)},
			})
			return
		case r.URL.Path == "/.well-known/agent-card.json":
			tr := true
			baseCard := &a2aspec.AgentCard{
				Name:        "Reference Live Upstream Agent",
				Description: "Cryptographically signed A2A v1.0 reference agent",
				Version:     "1.0.0",
				Capabilities: a2aspec.AgentCapabilities{
					Streaming:         &tr,
					PushNotifications: &tr,
					ExtendedAgentCard: &tr,
				},
				DefaultInputModes:  []string{"text/plain"},
				DefaultOutputModes: []string{"text/plain"},
				Skills: []a2aspec.AgentSkill{
					{Id: "audit", Name: "Live Audit", Description: "Runs live conformance checks", Tags: []string{"audit"}},
				},
				SupportedInterfaces: []a2aspec.AgentInterface{
					{ProtocolBinding: domain.A2AProtocolBindingHTTPJSON, ProtocolVersion: "1.0", Url: upstreamURL},
				},
			}
			signed := signCardES256JWS(t, upstreamKey, upstreamKID, baseCard)
			w.Header().Set("Content-Type", "application/a2a+json")
			_ = json.NewEncoder(w).Encode(signed)
			return
		case r.URL.Path == "/.well-known/tampered-card.json":
			tr := true
			baseCard := &a2aspec.AgentCard{
				Name:               "Tampered Upstream Agent",
				Description:        "Invalid signature",
				Version:            "1.0.0",
				Capabilities:       a2aspec.AgentCapabilities{Streaming: &tr},
				DefaultInputModes:  []string{"text/plain"},
				DefaultOutputModes: []string{"text/plain"},
				Skills:             []a2aspec.AgentSkill{},
				SupportedInterfaces: []a2aspec.AgentInterface{
					{ProtocolBinding: domain.A2AProtocolBindingHTTPJSON, ProtocolVersion: "1.0", Url: upstreamURL},
				},
			}
			signed := signCardES256JWS(t, upstreamKey, upstreamKID, baseCard)
			signed.Description = "TAMPERED AFTER SIGNING"
			w.Header().Set("Content-Type", "application/a2a+json")
			_ = json.NewEncoder(w).Encode(signed)
			return
		}

		// Verify Vault-decrypted custom auth header reaches upstream
		if got := r.Header.Get("X-Upstream-Secret"); got == expectedUpstreamSecret || got == "Bearer "+expectedUpstreamSecret {
			upstreamSecretHits.Add(1)
		}

		if r.URL.Path == "/message:stream" {
			w.Header().Set("Content-Type", "text/event-stream")
			flusher, _ := w.(http.Flusher)
			id := fmt.Sprintf("up_stream_%d", upstreamSeq.Add(1))
			ctxID := "ctx_stream_live"
			artName := "stream_chunk"
			frames := []a2aspec.StreamResponse{
				{
					StatusUpdate: &a2aspec.TaskStatusUpdateEvent{
						TaskId:    id,
						ContextId: ctxID,
						Status:    a2aspec.TaskStatus{State: a2aspec.TASKSTATEWORKING},
					},
				},
				{
					ArtifactUpdate: &a2aspec.TaskArtifactUpdateEvent{
						TaskId:    id,
						ContextId: ctxID,
						Artifact: a2aspec.Artifact{
							ArtifactId: "art_stream_1",
							Name:       &artName,
							Parts:      []a2aspec.Part{a2aspec.NewTextPart("Live streamed chunk")},
						},
					},
				},
				{
					StatusUpdate: &a2aspec.TaskStatusUpdateEvent{
						TaskId:    id,
						ContextId: ctxID,
						Status: a2aspec.TaskStatus{
							State: a2aspec.TASKSTATECOMPLETED,
							Message: &a2aspec.Message{
								MessageId: "msg_stream_done",
								Role:      a2aspec.ROLEAGENT,
								Parts:     []a2aspec.Part{a2aspec.NewTextPart("Stream finished")},
							},
						},
					},
				},
			}
			for _, f := range frames {
				b, _ := json.Marshal(f)
				_, _ = fmt.Fprintf(w, "data: %s\n\n", string(b))
				if flusher != nil {
					flusher.Flush()
				}
			}
			return
		}

		if strings.HasSuffix(r.URL.Path, ":cancel") {
			taskID := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/tasks/"), ":cancel")
			w.Header().Set("Content-Type", "application/a2a+json")
			_ = json.NewEncoder(w).Encode(a2aspec.Task{
				Id:     taskID,
				Status: a2aspec.TaskStatus{State: a2aspec.TASKSTATECANCELED},
			})
			return
		}

		// Default: /message:send
		rawBody, _ := io.ReadAll(r.Body)
		bodyStr := string(rawBody)
		state := a2aspec.TASKSTATEWORKING
		replyText := "Working on live request"
		switch {
		case strings.Contains(bodyStr, "COMPLETE_NOW") || strings.Contains(bodyStr, "AAPL"):
			state = a2aspec.TASKSTATECOMPLETED
			replyText = "Live assessment complete for AAPL"
		case strings.Contains(bodyStr, "NEED_INPUT"):
			state = a2aspec.TASKSTATEINPUTREQUIRED
			replyText = "Please clarify portfolio ticker"
		}
		ctxID := "ctx_live_" + runID
		var parsed a2aspec.SendMessageRequest
		if json.Unmarshal(rawBody, &parsed) == nil && parsed.Message.ContextId != nil && *parsed.Message.ContextId != "" {
			ctxID = *parsed.Message.ContextId
		}
		taskID := fmt.Sprintf("up_task_%d", upstreamSeq.Add(1))
		w.Header().Set("Content-Type", "application/a2a+json")
		respObj := a2aspec.NewSendMessageResponseTask(&a2aspec.Task{
			Id:        taskID,
			ContextId: &ctxID,
			Status: a2aspec.TaskStatus{
				State: state,
				Message: &a2aspec.Message{
					MessageId: "msg_up_" + taskID,
					Role:      a2aspec.ROLEAGENT,
					Parts:     []a2aspec.Part{a2aspec.NewTextPart(replyText)},
				},
			},
		})
		_ = json.NewEncoder(w).Encode(respObj)
	}))
	defer refUpstream.Close()
	upstreamURL = refUpstream.URL

	// 2. Push Notification Webhook Sink with toggleable 503 Chaos mode
	var sinkFail atomic.Bool
	var sinkMu sync.Mutex
	var sinkTokens []string
	var sinkAuths []string
	var sinkIdemKeys []string
	webhookSink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if sinkFail.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		sinkMu.Lock()
		sinkTokens = append(sinkTokens, r.Header.Get("X-A2A-Notification-Token"))
		sinkAuths = append(sinkAuths, r.Header.Get("Authorization"))
		sinkIdemKeys = append(sinkIdemKeys, r.Header.Get("X-Idempotency-Key"))
		sinkMu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer webhookSink.Close()

	// 3. Provision Org A, Org B, and Virtual Keys
	var orgA, orgB domain.Organization
	cluster.c1.doJSON(http.MethodPost, "/admin/v1/organizations", cluster.adminHdrs, map[string]any{
		"name": "Live Conformance Org A",
		"slug": "live-conf-a-" + runID,
	}, &orgA)
	cluster.c1.doJSON(http.MethodPost, "/admin/v1/organizations", cluster.adminHdrs, map[string]any{
		"name": "Live Conformance Org B",
		"slug": "live-conf-b-" + runID,
	}, &orgB)

	var vkA1, vkA2, vkB domain.VirtualKey
	cluster.c1.doJSON(http.MethodPost, "/admin/v1/keys", cluster.adminHdrs, map[string]any{
		"org_id":             orgA.ID,
		"name":               "live-a1",
		"allowed_endpoints":  []string{"*"},
		"allowed_a2a_agents": []string{"*"},
		"allowed_models":     []string{"*"},
	}, &vkA1)
	cluster.c1.doJSON(http.MethodPost, "/admin/v1/keys", cluster.adminHdrs, map[string]any{
		"org_id":             orgA.ID,
		"name":               "live-a2-idor",
		"allowed_endpoints":  []string{"*"},
		"allowed_a2a_agents": []string{"*"},
	}, &vkA2)
	cluster.c1.doJSON(http.MethodPost, "/admin/v1/keys", cluster.adminHdrs, map[string]any{
		"org_id":             orgB.ID,
		"name":               "live-b-cross-org",
		"allowed_endpoints":  []string{"*"},
		"allowed_a2a_agents": []string{"*"},
	}, &vkB)

	// 4. Register Agent with private card + Vault-encrypted custom header auth
	agentSlug := "live-ref-agent-" + runID
	var createdAgent struct {
		Agent domain.A2AAgent `json:"agent"`
	}
	extCardJSON, _ := json.Marshal(a2aspec.AgentCard{
		Name:               "Live Reference Extended Agent",
		Description:        "Authenticated extended agent card",
		Version:            "1.0.0",
		Capabilities:       a2aspec.AgentCapabilities{},
		DefaultInputModes:  []string{"text/plain"},
		DefaultOutputModes: []string{"text/plain"},
		Skills:             []a2aspec.AgentSkill{},
		SupportedInterfaces: []a2aspec.AgentInterface{
			{ProtocolBinding: domain.A2AProtocolBindingHTTPJSON, ProtocolVersion: "1.0", Url: refUpstream.URL},
		},
	})
	resp, raw := cluster.c1.doJSON(http.MethodPost, "/admin/v1/a2a/agents", cluster.adminHdrs, map[string]any{
		"org_id":                   orgA.ID,
		"name":                     "Live Reference Agent",
		"slug":                     agentSlug,
		"endpoint_url":             refUpstream.URL,
		"agent_card_url":           refUpstream.URL + "/.well-known/agent-card.json",
		"extended_agent_card_json": string(extCardJSON),
		"protocol_binding":         domain.A2AProtocolBindingHTTPJSON,
		"is_public_card":           false,
		"task_visibility_mode":     domain.TaskVisibilityKeyStrict,
		"auth_type":                "static",
		"auth_header_name":         "X-Upstream-Secret",
		"auth_secret":              expectedUpstreamSecret,
		"is_active":                true,
	}, &createdAgent)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create live A2A agent failed (%d): %s", resp.StatusCode, string(raw))
	}
	agentID := createdAgent.Agent.ID

	// --- SECTION A: Cryptographic JWS/JWKS Sync & Discovery Isolation ---
	t.Run("A_CryptographicCardSyncAndPublicPrivateDiscovery", func(t *testing.T) {
		// Reject tampered JWS card
		sc, _, body := doLiveHTTP(t, http.MethodPost,
			fmt.Sprintf("%s/admin/v1/a2a/agents/%s/sync-card", cluster.ts1.URL, agentID),
			e2eMasterAdminKey, "application/json",
			fmt.Sprintf(`{"agent_card_url":%q,"jwks_url":%q}`, refUpstream.URL+"/.well-known/tampered-card.json", refUpstream.URL+"/.well-known/jwks.json"),
			nil)
		if sc < 400 {
			t.Fatalf("expected tampered JWS card sync to be rejected, got %d: %s", sc, string(body))
		}

		// Accept valid ES256 JWS card verified against live JWKS
		sc, _, body = doLiveHTTP(t, http.MethodPost,
			fmt.Sprintf("%s/admin/v1/a2a/agents/%s/sync-card", cluster.ts1.URL, agentID),
			e2eMasterAdminKey, "application/json",
			fmt.Sprintf(`{"agent_card_url":%q,"jwks_url":%q}`, refUpstream.URL+"/.well-known/agent-card.json", refUpstream.URL+"/.well-known/jwks.json"),
			nil)
		if sc != http.StatusOK {
			t.Fatalf("expected valid ES256 JWS card sync 200, got %d: %s", sc, string(body))
		}

		// Private card must NOT be exposed unauthenticated or to Org B
		sc, _, _ = doLiveHTTP(t, http.MethodGet, cluster.ts1.URL+"/.well-known/agent-card.json?agent="+agentSlug, "", "", "", nil)
		if sc != http.StatusNotFound {
			t.Fatalf("expected 404 for unauthenticated private card discovery, got %d", sc)
		}
		sc, _, _ = doLiveHTTP(t, http.MethodGet, cluster.ts1.URL+"/.well-known/agent-card.json?agent="+agentSlug, vkB.RawKey, "", "", nil)
		if sc != http.StatusNotFound {
			t.Fatalf("expected 404 for cross-org private card discovery, got %d", sc)
		}

		// Flip is_public_card=true on Pod 1 and verify public discovery on Pod 2 passes OpenAPI AgentCard schema
		sc, _, body = doLiveHTTP(t, http.MethodPut,
			fmt.Sprintf("%s/admin/v1/a2a/agents/%s", cluster.ts1.URL, agentID),
			e2eMasterAdminKey, "application/json", `{"is_public_card":true}`, nil)
		if sc != http.StatusOK {
			t.Fatalf("PUT is_public_card failed (%d): %s", sc, string(body))
		}
		sc, _, cardRaw := doLiveHTTP(t, http.MethodGet, cluster.ts2.URL+"/.well-known/agent-card.json?agent="+agentSlug, "", "", "", nil)
		if sc != http.StatusOK {
			t.Fatalf("expected 200 for public card on Pod 2, got %d: %s", sc, string(cardRaw))
		}
		if err := a2aspec.ValidateSchema("AgentCard", cardRaw); err != nil {
			t.Fatalf("public AgentCard failed OpenAPI schema validation: %v\n%s", err, string(cardRaw))
		}
		// Legacy alias /.well-known/agent.json enabled
		sc, _, _ = doLiveHTTP(t, http.MethodGet, cluster.ts2.URL+"/.well-known/agent.json?agent="+agentSlug, "", "", "", nil)
		if sc != http.StatusOK {
			t.Fatalf("expected 200 for legacy /.well-known/agent.json, got %d", sc)
		}
	})

	// --- SECTION B: All 27 OpenAPI 3.1.0 Operations (Root & /{tenant}) + Dual-Node Subscribe-First SSE ---
	var primaryTaskID string
	t.Run("B_OpenAPIRESTAllPathsAndDualNodeSSE", func(t *testing.T) {
		// Invalid content-type returns google.rpc.StatusError
		sc, _, errRaw := doLiveHTTP(t, http.MethodPost,
			fmt.Sprintf("%s/a2a/v1/agents/%s/message:send", cluster.ts1.URL, agentSlug),
			vkA1.RawKey, "text/plain", `{}`, nil)
		if sc != http.StatusUnsupportedMediaType {
			t.Fatalf("expected 415 for text/plain, got %d: %s", sc, string(errRaw))
		}
		if err := a2aspec.ValidateSchema("GoogleRpcStatusError", errRaw); err != nil {
			t.Fatalf("error envelope failed GoogleRpcStatusError schema: %v\n%s", err, string(errRaw))
		}

		// POST /message:send on Pod 1
		sendBody := `{"message":{"messageId":"msg_live_1","contextId":"ctx_conformance","role":"ROLE_USER","parts":[{"text":"Start live conformance workflow"}]}}`
		sc, hdr, sendRaw := doLiveHTTP(t, http.MethodPost,
			fmt.Sprintf("%s/a2a/v1/agents/%s/message:send", cluster.ts1.URL, agentSlug),
			vkA1.RawKey, "application/a2a+json", sendBody, nil)
		if sc != http.StatusOK {
			t.Fatalf("POST /message:send failed (%d): %s", sc, string(sendRaw))
		}
		if hdr.Get("A2A-Version") != "1.0" {
			t.Fatalf("expected A2A-Version: 1.0, got %q", hdr.Get("A2A-Version"))
		}
		if err := a2aspec.ValidateSchema("SendMessageResponse", sendRaw); err != nil {
			t.Fatalf("SendMessageResponse failed OpenAPI schema: %v\n%s", err, string(sendRaw))
		}
		var smResp a2aspec.SendMessageResponse
		_ = json.Unmarshal(sendRaw, &smResp)
		if smResp.Task == nil || smResp.Task.Id == "" {
			t.Fatalf("expected task in SendMessageResponse: %s", string(sendRaw))
		}
		primaryTaskID = smResp.Task.Id

		// Tenant-scoped POST /{tenant}/message:send
		sc, _, tenSendRaw := doLiveHTTP(t, http.MethodPost,
			fmt.Sprintf("%s/a2a/v1/agents/%s/%s/message:send", cluster.ts1.URL, agentSlug, orgA.ID),
			vkA1.RawKey, "application/a2a+json",
			`{"message":{"messageId":"msg_live_tenant","contextId":"ctx_conformance","role":"ROLE_USER","parts":[{"text":"COMPLETE_NOW"}]}}`, nil)
		if sc != http.StatusOK {
			t.Fatalf("POST /{tenant}/message:send failed (%d): %s", sc, string(tenSendRaw))
		}
		if err := a2aspec.ValidateSchema("SendMessageResponse", tenSendRaw); err != nil {
			t.Fatalf("tenant SendMessageResponse failed OpenAPI schema: %v", err)
		}

		// GET /extendedAgentCard & GET /{tenant}/extendedAgentCard
		for _, path := range []string{
			fmt.Sprintf("/a2a/v1/agents/%s/extendedAgentCard", agentSlug),
			fmt.Sprintf("/a2a/v1/agents/%s/%s/extendedAgentCard", agentSlug, orgA.ID),
		} {
			sc, _, extRaw := doLiveHTTP(t, http.MethodGet, cluster.ts2.URL+path, vkA1.RawKey, "", "", nil)
			if sc != http.StatusOK {
				t.Fatalf("GET %s failed (%d): %s", path, sc, string(extRaw))
			}
			if err := a2aspec.ValidateSchema("AgentCard", extRaw); err != nil {
				t.Fatalf("extendedAgentCard schema invalid: %v", err)
			}
		}

		// GET /tasks & GET /{tenant}/tasks on Pod 2
		for _, path := range []string{
			fmt.Sprintf("/a2a/v1/agents/%s/tasks?contextId=ctx_conformance&pageSize=10", agentSlug),
			fmt.Sprintf("/a2a/v1/agents/%s/%s/tasks?pageSize=10", agentSlug, orgA.ID),
		} {
			sc, _, listRaw := doLiveHTTP(t, http.MethodGet, cluster.ts2.URL+path, vkA1.RawKey, "", "", nil)
			if sc != http.StatusOK {
				t.Fatalf("GET %s failed (%d): %s", path, sc, string(listRaw))
			}
			if err := a2aspec.ValidateSchema("ListTasksResponse", listRaw); err != nil {
				t.Fatalf("ListTasksResponse schema invalid: %v\n%s", err, string(listRaw))
			}
		}

		// GET /tasks/{id} & GET /{tenant}/tasks/{id} on Pod 2
		for _, path := range []string{
			fmt.Sprintf("/a2a/v1/agents/%s/tasks/%s", agentSlug, primaryTaskID),
			fmt.Sprintf("/a2a/v1/agents/%s/%s/tasks/%s", agentSlug, orgA.ID, primaryTaskID),
		} {
			sc, _, taskRaw := doLiveHTTP(t, http.MethodGet, cluster.ts2.URL+path, vkA1.RawKey, "", "", nil)
			if sc != http.StatusOK {
				t.Fatalf("GET %s failed (%d): %s", path, sc, string(taskRaw))
			}
			if err := a2aspec.ValidateSchema("Task", taskRaw); err != nil {
				t.Fatalf("Task schema invalid: %v\n%s", err, string(taskRaw))
			}
		}

		// Push Notification Config CRUD (both root & /{tenant})
		pushBody := fmt.Sprintf(`{"url":%q,"token":"live-notify-tok","authentication":{"scheme":"Bearer","credentials":"live-push-bearer"}}`, webhookSink.URL)
		sc, _, pcRaw := doLiveHTTP(t, http.MethodPost,
			fmt.Sprintf("%s/a2a/v1/agents/%s/tasks/%s/pushNotificationConfigs", cluster.ts1.URL, agentSlug, primaryTaskID),
			vkA1.RawKey, "application/a2a+json", pushBody, nil)
		if sc != http.StatusCreated && sc != http.StatusOK {
			t.Fatalf("create push config failed (%d): %s", sc, string(pcRaw))
		}
		if err := a2aspec.ValidateSchema("TaskPushNotificationConfig", pcRaw); err != nil {
			t.Fatalf("TaskPushNotificationConfig schema invalid: %v\n%s", err, string(pcRaw))
		}
		var pc1 a2aspec.TaskPushNotificationConfig
		_ = json.Unmarshal(pcRaw, &pc1)
		if pc1.Id == nil || *pc1.Id == "" {
			t.Fatalf("expected push config id: %s", string(pcRaw))
		}

		// Create 2nd push config via /{tenant}/... path
		sc, _, pc2Raw := doLiveHTTP(t, http.MethodPost,
			fmt.Sprintf("%s/a2a/v1/agents/%s/%s/tasks/%s/pushNotificationConfigs", cluster.ts1.URL, agentSlug, orgA.ID, primaryTaskID),
			vkA1.RawKey, "application/a2a+json", pushBody, nil)
		if sc != http.StatusCreated && sc != http.StatusOK {
			t.Fatalf("tenant create push config failed (%d): %s", sc, string(pc2Raw))
		}
		var pc2 a2aspec.TaskPushNotificationConfig
		_ = json.Unmarshal(pc2Raw, &pc2)

		// List & Get on Pod 2
		sc, _, listPCRaw := doLiveHTTP(t, http.MethodGet,
			fmt.Sprintf("%s/a2a/v1/agents/%s/tasks/%s/pushNotificationConfigs", cluster.ts2.URL, agentSlug, primaryTaskID),
			vkA1.RawKey, "", "", nil)
		if sc != http.StatusOK {
			t.Fatalf("list push configs failed (%d): %s", sc, string(listPCRaw))
		}
		if err := a2aspec.ValidateSchema("ListTaskPushNotificationConfigsResponse", listPCRaw); err != nil {
			t.Fatalf("ListTaskPushNotificationConfigsResponse schema invalid: %v", err)
		}
		sc, _, getPCRaw := doLiveHTTP(t, http.MethodGet,
			fmt.Sprintf("%s/a2a/v1/agents/%s/%s/tasks/%s/pushNotificationConfigs/%s", cluster.ts2.URL, agentSlug, orgA.ID, primaryTaskID, *pc2.Id),
			vkA1.RawKey, "", "", nil)
		if sc != http.StatusOK {
			t.Fatalf("tenant get push config failed (%d): %s", sc, string(getPCRaw))
		}
		sc, _, _ = doLiveHTTP(t, http.MethodDelete,
			fmt.Sprintf("%s/a2a/v1/agents/%s/%s/tasks/%s/pushNotificationConfigs/%s", cluster.ts2.URL, agentSlug, orgA.ID, primaryTaskID, *pc2.Id),
			vkA1.RawKey, "", "", nil)
		if sc != http.StatusNoContent && sc != http.StatusOK {
			t.Fatalf("tenant delete push config failed (%d)", sc)
		}

		// POST /message:stream (root & /{tenant})
		for _, path := range []string{
			fmt.Sprintf("/a2a/v1/agents/%s/message:stream", agentSlug),
			fmt.Sprintf("/a2a/v1/agents/%s/%s/message:stream", agentSlug, orgA.ID),
		} {
			sc, shdr, streamRaw := doLiveHTTP(t, http.MethodPost, cluster.ts1.URL+path, vkA1.RawKey, "application/a2a+json", sendBody, nil)
			if sc != http.StatusOK || !strings.Contains(shdr.Get("Content-Type"), "text/event-stream") {
				t.Fatalf("POST %s failed (%d, ct=%q): %s", path, sc, shdr.Get("Content-Type"), string(streamRaw))
			}
			if !strings.Contains(string(streamRaw), "Stream finished") {
				t.Fatalf("POST %s missing expected streamed chunk: %s", path, string(streamRaw))
			}
		}

		// Dual-Node Subscribe-First SSE: subscribe on Pod 2 while Pod 1 cancels primaryTaskID
		subCtx, subCancel := context.WithTimeout(ctx, 5*time.Second)
		defer subCancel()
		subReq, _ := http.NewRequestWithContext(subCtx, http.MethodGet,
			fmt.Sprintf("%s/a2a/v1/agents/%s/tasks/%s:subscribe", cluster.ts2.URL, agentSlug, primaryTaskID), nil)
		subReq.Header.Set("Authorization", "Bearer "+vkA1.RawKey)
		subResp, err := http.DefaultClient.Do(subReq)
		if err != nil {
			t.Fatalf("subscribe SSE on Pod 2: %v", err)
		}
		defer subResp.Body.Close()
		if subResp.StatusCode != http.StatusOK {
			b, _ := io.ReadAll(subResp.Body)
			t.Fatalf("subscribe SSE status=%d: %s", subResp.StatusCode, string(b))
		}

		gotCancelEvent := make(chan bool, 1)
		go func() {
			scanner := bufio.NewScanner(subResp.Body)
			for scanner.Scan() {
				line := scanner.Text()
				if strings.HasPrefix(line, "data:") && strings.Contains(line, "TASK_STATE_CANCELED") {
					gotCancelEvent <- true
					return
				}
			}
			gotCancelEvent <- false
		}()

		time.Sleep(150 * time.Millisecond)
		sc, _, cancelRaw := doLiveHTTP(t, http.MethodPost,
			fmt.Sprintf("%s/a2a/v1/agents/%s/tasks/%s:cancel", cluster.ts1.URL, agentSlug, primaryTaskID),
			vkA1.RawKey, "application/a2a+json", `{}`, nil)
		if sc != http.StatusOK {
			t.Fatalf("POST /tasks/{id}:cancel failed (%d): %s", sc, string(cancelRaw))
		}
		if err := a2aspec.ValidateSchema("Task", cancelRaw); err != nil {
			t.Fatalf("canceled Task schema invalid: %v", err)
		}

		select {
		case ok := <-gotCancelEvent:
			if !ok {
				t.Fatalf("Pod 2 SSE stream closed without receiving TASK_STATE_CANCELED from Pod 1")
			}
		case <-time.After(4 * time.Second):
			t.Fatalf("timed out waiting for Pod 2 Subscribe-First SSE event from Pod 1")
		}

		// Verify POST /tasks/{id}:subscribe compat & Last-Event-ID replay on terminal task
		sc, _, postSubRaw := doLiveHTTP(t, http.MethodPost,
			fmt.Sprintf("%s/a2a/v1/agents/%s/tasks/%s:subscribe", cluster.ts2.URL, agentSlug, primaryTaskID),
			vkA1.RawKey, "application/a2a+json", `{}`, map[string]string{"Last-Event-ID": "0"})
		if sc != http.StatusOK || !strings.Contains(string(postSubRaw), "TASK_STATE_CANCELED") {
			t.Fatalf("POST :subscribe compat failed (%d): %s", sc, string(postSubRaw))
		}
	})

	// --- SECTION C: All 11 JSON-RPC 2.0 PascalCase Methods ---
	t.Run("C_JSONRPC20AllMethods", func(t *testing.T) {
		callRPC := func(endpoint, method string, params any) (int, map[string]any, []byte) {
			reqBody, _ := json.Marshal(map[string]any{
				"jsonrpc": "2.0",
				"id":      "rpc-" + method,
				"method":  method,
				"params":  params,
			})
			sc, _, raw := doLiveHTTP(t, http.MethodPost, endpoint, vkA1.RawKey, "application/json", string(reqBody), nil)
			var out map[string]any
			_ = json.Unmarshal(raw, &out)
			return sc, out, raw
		}

		rpcEndpoint := fmt.Sprintf("%s/a2a/v1/agents/%s", cluster.ts1.URL, agentSlug)
		tenantRPCEndpoint := fmt.Sprintf("%s/a2a/v1/agents/%s/%s", cluster.ts2.URL, agentSlug, orgA.ID)

		// 1. SendMessage
		sc, out, raw := callRPC(rpcEndpoint, "SendMessage", map[string]any{
			"message": map[string]any{
				"messageId": "rpc_msg_1",
				"role":      "ROLE_USER",
				"parts":     []map[string]any{{"text": "JSON-RPC SendMessage"}},
			},
		})
		if sc != http.StatusOK || out["error"] != nil {
			t.Fatalf("JSON-RPC SendMessage failed (%d): %s", sc, string(raw))
		}
		rpcTaskID := out["result"].(map[string]any)["task"].(map[string]any)["id"].(string)

		// 2. GetTask (via tenant JSON-RPC endpoint on Pod 2)
		if sc, out, raw := callRPC(tenantRPCEndpoint, "GetTask", map[string]any{"id": rpcTaskID}); sc != http.StatusOK || out["error"] != nil {
			t.Fatalf("JSON-RPC GetTask failed (%d): %s", sc, string(raw))
		}
		// 3. ListTasks
		if sc, out, raw := callRPC(rpcEndpoint, "ListTasks", map[string]any{"pageSize": 5}); sc != http.StatusOK || out["error"] != nil {
			t.Fatalf("JSON-RPC ListTasks failed (%d): %s", sc, string(raw))
		}
		// 4. CreateTaskPushNotificationConfig
		sc, out, raw = callRPC(rpcEndpoint, "CreateTaskPushNotificationConfig", map[string]any{
			"taskId": rpcTaskID,
			"url":    webhookSink.URL,
			"token":  "rpc-tok",
		})
		if sc != http.StatusOK || out["error"] != nil {
			t.Fatalf("JSON-RPC CreateTaskPushNotificationConfig failed (%d): %s", sc, string(raw))
		}
		rpcPushID := out["result"].(map[string]any)["id"].(string)
		// 5. GetTaskPushNotificationConfig
		if sc, out, raw := callRPC(rpcEndpoint, "GetTaskPushNotificationConfig", map[string]any{"taskId": rpcTaskID, "id": rpcPushID}); sc != http.StatusOK || out["error"] != nil {
			t.Fatalf("JSON-RPC GetTaskPushNotificationConfig failed (%d): %s", sc, string(raw))
		}
		// 6. ListTaskPushNotificationConfigs
		if sc, out, raw := callRPC(rpcEndpoint, "ListTaskPushNotificationConfigs", map[string]any{"taskId": rpcTaskID}); sc != http.StatusOK || out["error"] != nil {
			t.Fatalf("JSON-RPC ListTaskPushNotificationConfigs failed (%d): %s", sc, string(raw))
		}
		// 7. DeleteTaskPushNotificationConfig
		if sc, out, raw := callRPC(rpcEndpoint, "DeleteTaskPushNotificationConfig", map[string]any{"taskId": rpcTaskID, "id": rpcPushID}); sc != http.StatusOK || out["error"] != nil {
			t.Fatalf("JSON-RPC DeleteTaskPushNotificationConfig failed (%d): %s", sc, string(raw))
		}
		// 8. GetExtendedAgentCard
		if sc, out, raw := callRPC(rpcEndpoint, "GetExtendedAgentCard", map[string]any{}); sc != http.StatusOK || out["error"] != nil {
			t.Fatalf("JSON-RPC GetExtendedAgentCard failed (%d): %s", sc, string(raw))
		}
		// 9. CancelTask
		if sc, out, raw := callRPC(rpcEndpoint, "CancelTask", map[string]any{"id": rpcTaskID}); sc != http.StatusOK || out["error"] != nil {
			t.Fatalf("JSON-RPC CancelTask failed (%d): %s", sc, string(raw))
		}
		// 10. SendStreamingMessage (returns text/event-stream)
		streamRPCReq, _ := json.Marshal(map[string]any{
			"jsonrpc": "2.0",
			"id":      "rpc-stream-1",
			"method":  "SendStreamingMessage",
			"params": map[string]any{
				"message": map[string]any{
					"messageId": "rpc_s_1",
					"role":      "ROLE_USER",
					"parts":     []map[string]any{{"text": "stream via rpc"}},
				},
			},
		})
		sc, shdr, sraw := doLiveHTTP(t, http.MethodPost, rpcEndpoint, vkA1.RawKey, "application/json", string(streamRPCReq), nil)
		if sc != http.StatusOK || !strings.Contains(shdr.Get("Content-Type"), "text/event-stream") {
			t.Fatalf("JSON-RPC SendStreamingMessage failed (%d, ct=%q): %s", sc, shdr.Get("Content-Type"), string(sraw))
		}
		// 11. SubscribeToTask (returns text/event-stream)
		subRPCReq, _ := json.Marshal(map[string]any{
			"jsonrpc": "2.0",
			"id":      "rpc-sub-1",
			"method":  "SubscribeToTask",
			"params":  map[string]any{"id": rpcTaskID},
		})
		sc, shdr, sraw = doLiveHTTP(t, http.MethodPost, rpcEndpoint, vkA1.RawKey, "application/json", string(subRPCReq), nil)
		if sc != http.StatusOK || !strings.Contains(shdr.Get("Content-Type"), "text/event-stream") {
			t.Fatalf("JSON-RPC SubscribeToTask failed (%d, ct=%q): %s", sc, shdr.Get("Content-Type"), string(sraw))
		}
		// Unknown method returns JSON-RPC -32601
		sc, out, raw = callRPC(rpcEndpoint, "tasks/send", map[string]any{})
		errObj, _ := out["error"].(map[string]any)
		if sc != http.StatusOK || errObj == nil || int(errObj["code"].(float64)) != -32601 {
			t.Fatalf("expected JSON-RPC -32601 for legacy tasks/send, got %d: %s", sc, string(raw))
		}
	})

	// --- SECTION D: All 11 Native gRPC RPCs over Real TCP Socket ---
	t.Run("D_NativeGRPCAll11RPCsOverRealTCP", func(t *testing.T) {
		lis, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen tcp: %v", err)
		}
		grpcSrv := grpc.NewServer()
		rbac := auth.NewRBACEngine(cluster.pgRepo)
		authSvc := auth.NewService(cluster.pgRepo, cluster.redisFabric, e2eMasterAdminKey, 10*time.Second, time.Minute)
		a2aGRPC := a2a.NewGRPCServer(cluster.node1.A2ARouter(), authSvc, rbac)
		a2aGRPC.SetAuthResolver(cluster.node1.AuthResolver())
		a2aGRPC.SetStreamSubscriber(cluster.node1.A2AStreamSubscriber())
		a2aGRPC.Register(grpcSrv)
		go func() { _ = grpcSrv.Serve(lis) }()
		defer grpcSrv.Stop()

		conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			t.Fatalf("grpc dial tcp: %v", err)
		}
		defer conn.Close()
		gc := pb.NewA2AServiceClient(conn)

		// Unauthenticated call must fail with codes.Unauthenticated
		if _, err := gc.GetExtendedAgentCard(ctx, &pb.GetExtendedAgentCardRequest{}); status.Code(err) != codes.Unauthenticated {
			t.Fatalf("expected Unauthenticated for anonymous gRPC call, got %v", err)
		}

		mdCtx := metadata.NewOutgoingContext(ctx, metadata.Pairs(
			"authorization", "Bearer "+vkA1.RawKey,
			"x-a2a-agent-slug", agentSlug,
		))

		// 1. SendMessage
		sm, err := gc.SendMessage(mdCtx, &pb.SendMessageRequest{
			Message: &pb.Message{
				MessageId: "grpc_msg_1",
				Role:      pb.Role_ROLE_USER,
				Parts:     []*pb.Part{{Content: &pb.Part_Text{Text: "gRPC live 11-RPC check"}}},
			},
		})
		if err != nil || sm.GetTask() == nil {
			t.Fatalf("gRPC SendMessage failed: %v", err)
		}
		gTaskID := sm.GetTask().GetId()

		// 2. GetTask
		if gt, err := gc.GetTask(mdCtx, &pb.GetTaskRequest{Id: gTaskID}); err != nil || gt.GetId() != gTaskID {
			t.Fatalf("gRPC GetTask failed: %v", err)
		}
		// 3. ListTasks
		ps10 := int32(10)
		if lt, err := gc.ListTasks(mdCtx, &pb.ListTasksRequest{PageSize: &ps10}); err != nil || len(lt.GetTasks()) == 0 {
			t.Fatalf("gRPC ListTasks failed: %v", err)
		}
		// 4. CreateTaskPushNotificationConfig
		pc, err := gc.CreateTaskPushNotificationConfig(mdCtx, &pb.TaskPushNotificationConfig{
			TaskId: gTaskID,
			Url:    webhookSink.URL,
			Token:  "grpc-push-tok",
		})
		if err != nil || pc.GetId() == "" {
			t.Fatalf("gRPC CreateTaskPushNotificationConfig failed: %v", err)
		}
		// 5. GetTaskPushNotificationConfig
		if _, err := gc.GetTaskPushNotificationConfig(mdCtx, &pb.GetTaskPushNotificationConfigRequest{TaskId: gTaskID, Id: pc.GetId()}); err != nil {
			t.Fatalf("gRPC GetTaskPushNotificationConfig failed: %v", err)
		}
		// 6. ListTaskPushNotificationConfigs
		if lp, err := gc.ListTaskPushNotificationConfigs(mdCtx, &pb.ListTaskPushNotificationConfigsRequest{TaskId: gTaskID}); err != nil || len(lp.GetConfigs()) == 0 {
			t.Fatalf("gRPC ListTaskPushNotificationConfigs failed: %v", err)
		}
		// 7. DeleteTaskPushNotificationConfig
		if _, err := gc.DeleteTaskPushNotificationConfig(mdCtx, &pb.DeleteTaskPushNotificationConfigRequest{TaskId: gTaskID, Id: pc.GetId()}); err != nil {
			t.Fatalf("gRPC DeleteTaskPushNotificationConfig failed: %v", err)
		}
		// 8. GetExtendedAgentCard
		if card, err := gc.GetExtendedAgentCard(mdCtx, &pb.GetExtendedAgentCardRequest{}); err != nil || card.GetName() == "" {
			t.Fatalf("gRPC GetExtendedAgentCard failed: %v", err)
		}
		// 9. CancelTask
		if ct, err := gc.CancelTask(mdCtx, &pb.CancelTaskRequest{Id: gTaskID}); err != nil || ct.GetStatus().GetState() != pb.TaskState_TASK_STATE_CANCELED {
			t.Fatalf("gRPC CancelTask failed: %v (state=%v)", err, ct.GetStatus().GetState())
		}
		// 10. SubscribeToTask (replays terminal events)
		subStream, err := gc.SubscribeToTask(mdCtx, &pb.SubscribeToTaskRequest{Id: gTaskID})
		if err != nil {
			t.Fatalf("gRPC SubscribeToTask failed: %v", err)
		}
		if _, err := subStream.Recv(); err != nil {
			t.Fatalf("gRPC SubscribeToTask Recv failed: %v", err)
		}
		// 11. SendStreamingMessage
		msgStream, err := gc.SendStreamingMessage(mdCtx, &pb.SendMessageRequest{
			Message: &pb.Message{
				MessageId: "grpc_stream_1",
				Role:      pb.Role_ROLE_USER,
				Parts:     []*pb.Part{{Content: &pb.Part_Text{Text: "gRPC streaming check"}}},
			},
		})
		if err != nil {
			t.Fatalf("gRPC SendStreamingMessage failed: %v", err)
		}
		streamFrames := 0
		for {
			_, rerr := msgStream.Recv()
			if rerr == io.EOF {
				break
			}
			if rerr != nil {
				t.Fatalf("gRPC SendStreamingMessage Recv error: %v", rerr)
			}
			streamFrames++
		}
		if streamFrames == 0 {
			t.Fatalf("expected >= 1 gRPC SendStreamingMessage frames")
		}
	})

	// --- SECTION E: Cross-Key IDOR, Cross-Node Kill-Switch, Vault KEK Rotation & Outbox Chaos Replay ---
	t.Run("E_SecurityIsolation_KillSwitch_KEKRotation_And_OutboxChaosReplay", func(t *testing.T) {
		// IDOR check: vkA2 (same org, different key) must NOT access vkA1's key_strict task
		sc, _, _ := doLiveHTTP(t, http.MethodGet,
			fmt.Sprintf("%s/a2a/v1/agents/%s/tasks/%s", cluster.ts2.URL, agentSlug, primaryTaskID),
			vkA2.RawKey, "", "", nil)
		if sc != http.StatusForbidden && sc != http.StatusNotFound {
			t.Fatalf("expected 403/404 for cross-key IDOR on key_strict task, got %d", sc)
		}
		// Cross-org check: vkB must NOT access Org A agent
		sc, _, _ = doLiveHTTP(t, http.MethodGet,
			fmt.Sprintf("%s/a2a/v1/agents/%s/tasks", cluster.ts2.URL, agentSlug),
			vkB.RawKey, "", "", nil)
		if sc != http.StatusForbidden && sc != http.StatusNotFound {
			t.Fatalf("expected 403/404 for cross-org access, got %d", sc)
		}

		// Cross-node Kill-Switch: kill on Pod 1 -> immediately blocked on Pod 2 -> revive
		sc, _, _ = doLiveHTTP(t, http.MethodPost,
			fmt.Sprintf("%s/admin/v1/a2a/agents/%s/kill-switch", cluster.ts1.URL, agentID),
			e2eMasterAdminKey, "application/json", `{"killed":true}`, nil)
		if sc != http.StatusOK {
			t.Fatalf("kill-switch enable failed (%d)", sc)
		}
		sc, _, _ = doLiveHTTP(t, http.MethodPost,
			fmt.Sprintf("%s/a2a/v1/agents/%s/message:send", cluster.ts2.URL, agentSlug),
			vkA1.RawKey, "application/a2a+json",
			`{"message":{"messageId":"k1","role":"ROLE_USER","parts":[{"text":"blocked"}]}}`, nil)
		if sc != http.StatusServiceUnavailable {
			t.Fatalf("expected 503 on Pod 2 when killed on Pod 1, got %d", sc)
		}
		sc, _, _ = doLiveHTTP(t, http.MethodPost,
			fmt.Sprintf("%s/admin/v1/a2a/agents/%s/kill-switch", cluster.ts1.URL, agentID),
			e2eMasterAdminKey, "application/json", `{"killed":false}`, nil)
		if sc != http.StatusOK {
			t.Fatalf("kill-switch revive failed (%d)", sc)
		}

		// Vault KEK Rotation: clean any stale non-vault DEK rows from prior storage tests, rotate KEK -> newKEK,
		// verify encrypted agent secret + push config continue working, then rotate back to e2eMasterEncryptionKey.
		_, _ = cluster.pool.Exec(ctx, `DELETE FROM virtual_keys WHERE staged_key_dek IS NOT NULL AND staged_key_dek !~ '^[0-9a-fA-F]+$'`)
		newKEK := "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
		sc, _, kekRaw := doLiveHTTP(t, http.MethodPost,
			cluster.ts1.URL+"/admin/v1/security/rotate-kek",
			e2eMasterAdminKey, "application/json",
			fmt.Sprintf(`{"new_master_key":%q}`, newKEK), nil)
		if sc != http.StatusOK {
			t.Fatalf("rotate-kek failed (%d): %s", sc, string(kekRaw))
		}
		defer func() {
			_, _, _ = doLiveHTTP(t, http.MethodPost,
				cluster.ts1.URL+"/admin/v1/security/rotate-kek",
				e2eMasterAdminKey, "application/json",
				fmt.Sprintf(`{"new_master_key":%q}`, e2eMasterEncryptionKey), nil)
		}()
		beforeHits := upstreamSecretHits.Load()
		sc, _, postKEKRaw := doLiveHTTP(t, http.MethodPost,
			fmt.Sprintf("%s/a2a/v1/agents/%s/message:send", cluster.ts1.URL, agentSlug),
			vkA1.RawKey, "application/a2a+json",
			`{"message":{"messageId":"post_kek_1","role":"ROLE_USER","parts":[{"text":"post-kek dispatch"}]}}`, nil)
		if sc != http.StatusOK {
			t.Fatalf("post-KEK SendMessage failed (%d): %s", sc, string(postKEKRaw))
		}
		if upstreamSecretHits.Load() <= beforeHits {
			t.Fatalf("expected Vault-decrypted X-Upstream-Secret header to reach upstream after KEK rotation")
		}

		// Outbox Chaos: toggle Webhook Sink 503, seed dead_letter outbox event, restore Sink, replay via Admin API
		sinkFail.Store(true)
		var postKEKResp a2aspec.SendMessageResponse
		_ = json.Unmarshal(postKEKRaw, &postKEKResp)
		chaosTaskID := postKEKResp.Task.Id

		sc, _, pcChaosRaw := doLiveHTTP(t, http.MethodPost,
			fmt.Sprintf("%s/a2a/v1/agents/%s/tasks/%s/pushNotificationConfigs", cluster.ts1.URL, agentSlug, chaosTaskID),
			vkA1.RawKey, "application/a2a+json",
			fmt.Sprintf(`{"url":%q,"token":"chaos-verify-tok","authentication":{"scheme":"Bearer","credentials":"chaos-bearer"}}`, webhookSink.URL), nil)
		if sc != http.StatusCreated && sc != http.StatusOK {
			t.Fatalf("create chaos push config failed (%d): %s", sc, string(pcChaosRaw))
		}
		// Trigger status event while sink returns 503 -> outbox retries & transitions to dead_letter
		sc, _, _ = doLiveHTTP(t, http.MethodPost,
			fmt.Sprintf("%s/a2a/v1/agents/%s/tasks/%s:cancel", cluster.ts1.URL, agentSlug, chaosTaskID),
			vkA1.RawKey, "application/a2a+json", `{}`, nil)
		if sc != http.StatusOK {
			t.Fatalf("cancel chaosTask failed (%d)", sc)
		}

		var deadEventID string
		deadline := time.Now().Add(6 * time.Second)
		for time.Now().Before(deadline) {
			sc, _, obRaw := doLiveHTTP(t, http.MethodGet,
				fmt.Sprintf("%s/admin/v1/a2a/outbox?org_id=%s&status=dead_letter&limit=20", cluster.ts1.URL, orgA.ID),
				e2eMasterAdminKey, "", "", nil)
			if sc == http.StatusOK {
				var obResp struct {
					Events []domain.A2AOutboxEvent `json:"events"`
				}
				_ = json.Unmarshal(obRaw, &obResp)
				for _, ev := range obResp.Events {
					if ev.TaskID == chaosTaskID {
						deadEventID = ev.ID
						break
					}
				}
				if deadEventID != "" {
					break
				}
			}
			time.Sleep(100 * time.Millisecond)
		}
		if deadEventID == "" {
			t.Fatalf("expected outbox event for task %s to reach dead_letter under sink 503", chaosTaskID)
		}

		// Restore sink and replay via POST /admin/v1/a2a/outbox/{id}/replay
		sinkFail.Store(false)
		sc, _, replayRaw := doLiveHTTP(t, http.MethodPost,
			fmt.Sprintf("%s/admin/v1/a2a/outbox/%s/replay", cluster.ts1.URL, deadEventID),
			e2eMasterAdminKey, "application/json", `{}`, nil)
		if sc != http.StatusOK {
			t.Fatalf("outbox replay failed (%d): %s", sc, string(replayRaw))
		}

		// Verify webhook delivered with decrypted X-A2A-Notification-Token & Authorization header
		delivered := false
		deadline = time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			sinkMu.Lock()
			for i, tok := range sinkTokens {
				if tok == "chaos-verify-tok" && sinkAuths[i] == "Bearer chaos-bearer" {
					delivered = true
					break
				}
			}
			sinkMu.Unlock()
			if delivered {
				break
			}
			time.Sleep(50 * time.Millisecond)
		}
		if !delivered {
			t.Fatalf("expected replayed outbox event to deliver chaos-verify-tok + Bearer chaos-bearer")
		}
	})

	// --- SECTION F: OpenAI Bridge Multi-Turn Resumption + Public Go SDK ---
	t.Run("F_OpenAIBridgeMultiTurnAndPublicGoSDK", func(t *testing.T) {
		// Turn 1: INPUT_REQUIRED
		var turn1 struct {
			ID      string `json:"id"`
			Choices []struct {
				Message struct {
					Content string `json:"content"`
				} `json:"message"`
			} `json:"choices"`
		}
		sc, _, raw1 := doLiveHTTP(t, http.MethodPost, cluster.ts1.URL+"/v1/chat/completions", vkA1.RawKey, "application/json",
			fmt.Sprintf(`{"model":"a2a/%s","messages":[{"role":"user","content":"NEED_INPUT portfolio"}]}`, agentSlug), nil)
		if sc != http.StatusOK {
			t.Fatalf("bridge turn 1 failed (%d): %s", sc, string(raw1))
		}
		_ = json.Unmarshal(raw1, &turn1)
		if len(turn1.Choices) == 0 || !strings.Contains(turn1.Choices[0].Message.Content, "clarify") {
			t.Fatalf("unexpected turn 1 bridge output: %s", string(raw1))
		}
		// Turn 2: Resume and complete
		sc, _, raw2 := doLiveHTTP(t, http.MethodPost, cluster.ts1.URL+"/v1/chat/completions", vkA1.RawKey, "application/json",
			fmt.Sprintf(`{"model":"a2a/%s","messages":[{"role":"user","content":"NEED_INPUT portfolio"},{"role":"assistant","content":%q},{"role":"user","content":"AAPL"}]}`, agentSlug, turn1.Choices[0].Message.Content), nil)
		if sc != http.StatusOK || !strings.Contains(string(raw2), "AAPL") {
			t.Fatalf("bridge turn 2 failed (%d): %s", sc, string(raw2))
		}

		// Public Go SDK end-to-end against live Postgres + Redis gateway
		sdkClient := gateway.NewClient(cluster.ts1.URL, vkA1.RawKey)
		card, err := sdkClient.GetWellKnownAgentCard(ctx, agentSlug)
		if err != nil || card["name"] == "" {
			t.Fatalf("SDK GetWellKnownAgentCard: %v card=%v", err, card)
		}
		sendRes, err := sdkClient.SendA2AMessage(ctx, agentSlug, &gateway.A2ASendMessageRequest{
			Message: gateway.A2AMessage{
				MessageId: "sdk_live_1",
				Role:      "ROLE_USER",
				Parts:     []gateway.A2APart{{Text: "SDK live call"}},
			},
		})
		if err != nil || sendRes.Task == nil {
			t.Fatalf("SDK SendA2AMessage: %v", err)
		}
		gotTask, err := sdkClient.GetA2ATask(ctx, agentSlug, sendRes.Task.Id)
		if err != nil || gotTask.Id != sendRes.Task.Id {
			t.Fatalf("SDK GetA2ATask: %v", err)
		}
		listed, err := sdkClient.ListA2ATasks(ctx, agentSlug, &gateway.A2AListTasksRequest{PageSize: 10})
		if err != nil || len(listed.Tasks) == 0 {
			t.Fatalf("SDK ListA2ATasks: %v", err)
		}
		extCard, err := sdkClient.GetA2AExtendedAgentCard(ctx, agentSlug)
		if err != nil || extCard["name"] == "" {
			t.Fatalf("SDK GetA2AExtendedAgentCard: %v", err)
		}
		if _, err := sdkClient.CancelA2ATask(ctx, agentSlug, sendRes.Task.Id); err != nil {
			t.Fatalf("SDK CancelA2ATask: %v", err)
		}

		adminSDK := gateway.NewClient(cluster.ts1.URL, e2eMasterAdminKey)
		if _, err := adminSDK.ListA2AOutboxEvents(ctx, orgA.ID, "", 10); err != nil {
			t.Fatalf("SDK ListA2AOutboxEvents: %v", err)
		}
		if err := adminSDK.DeleteA2AAgent(ctx, agentID); err != nil {
			t.Fatalf("SDK DeleteA2AAgent: %v", err)
		}
	})

	// --- SECTION G: Outbound GRPC/JSONRPC Bindings, Retention Pruning, & Prometheus Metrics ---
	t.Run("G_OutboundBindings_RetentionPruning_TracePropagation_And_PrometheusMetrics", func(t *testing.T) {
		// 1. Stand up live upstream gRPC agent server and register protocol_binding = "GRPC"
		upLis, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen upstream gRPC: %v", err)
		}
		upGRPCSrv := grpc.NewServer()
		pb.RegisterA2AServiceServer(upGRPCSrv, &liveE2EUpstreamGRPCAgent{})
		go func() {
			_ = upGRPCSrv.Serve(upLis)
		}()
		defer upGRPCSrv.Stop()

		grpcSlug := "live-grpc-bound-agent-" + runID
		sc, _, rawReg := doLiveHTTP(t, http.MethodPost, cluster.ts1.URL+"/admin/v1/a2a/agents", e2eMasterAdminKey, "application/json",
			fmt.Sprintf(`{
				"org_id": %q,
				"slug": %q,
				"name": "Live Outbound gRPC Agent",
				"endpoint_url": %q,
				"protocol_binding": "GRPC",
				"auth_type": "none",
				"task_visibility_mode": "team",
				"is_active": true
			}`, orgA.ID, grpcSlug, "grpc://"+upLis.Addr().String()), nil)
		if sc != http.StatusCreated {
			t.Fatalf("register outbound gRPC agent failed (%d): %s", sc, string(rawReg))
		}

		// Invoke HTTP+JSON gateway -> outbound gRPC upstream agent
		sc, _, rawSend := doLiveHTTP(t, http.MethodPost, cluster.ts1.URL+"/a2a/v1/agents/"+grpcSlug+"/message:send", vkA1.RawKey, "application/a2a+json",
			`{"message":{"messageId":"m_grpc_e2e_1","role":"ROLE_USER","parts":[{"text":"ping outbound grpc"}]}}`,
			map[string]string{"A2A-Version": "1.0"})
		if sc != http.StatusOK || !strings.Contains(string(rawSend), "live gRPC response: ping outbound grpc") {
			t.Fatalf("outbound gRPC SendMessage failed (%d): %s", sc, string(rawSend))
		}

		// 2. Stand up live upstream JSON-RPC 2.0 agent server and register protocol_binding = "JSONRPC"
		upJSONRPCSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var rpcReq map[string]any
			_ = json.NewDecoder(r.Body).Decode(&rpcReq)
			w.Header().Set("Content-Type", "application/a2a+json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"jsonrpc": "2.0",
				"id":      rpcReq["id"],
				"result": map[string]any{
					"message": map[string]any{
						"messageId": "m_jsonrpc_reply_1",
						"role":      "ROLE_AGENT",
						"parts":     []map[string]any{{"text": "live JSON-RPC 2.0 response"}},
					},
				},
			})
		}))
		defer upJSONRPCSrv.Close()

		jsonrpcSlug := "live-jsonrpc-bound-agent-" + runID
		sc, _, rawRegJRPC := doLiveHTTP(t, http.MethodPost, cluster.ts1.URL+"/admin/v1/a2a/agents", e2eMasterAdminKey, "application/json",
			fmt.Sprintf(`{
				"org_id": %q,
				"slug": %q,
				"name": "Live Outbound JSONRPC Agent",
				"endpoint_url": %q,
				"protocol_binding": "JSONRPC",
				"auth_type": "none",
				"task_visibility_mode": "team",
				"is_active": true
			}`, orgA.ID, jsonrpcSlug, upJSONRPCSrv.URL), nil)
		if sc != http.StatusCreated {
			t.Fatalf("register outbound JSONRPC agent failed (%d): %s", sc, string(rawRegJRPC))
		}

		sc, _, rawSendJRPC := doLiveHTTP(t, http.MethodPost, cluster.ts1.URL+"/a2a/v1/agents/"+jsonrpcSlug+"/message:send", vkA1.RawKey, "application/a2a+json",
			`{"message":{"messageId":"m_jrpc_e2e_1","role":"ROLE_USER","parts":[{"text":"ping outbound jsonrpc"}]}}`,
			map[string]string{"A2A-Version": "1.0"})
		if sc != http.StatusOK || !strings.Contains(string(rawSendJRPC), "live JSON-RPC 2.0 response") {
			t.Fatalf("outbound JSONRPC SendMessage failed (%d): %s", sc, string(rawSendJRPC))
		}

		// 3. Execute live Postgres retention pruning for published stream rows and delivered outbox rows
		cutoff := time.Now().UTC().Add(1 * time.Hour)
		prunedCount, err := cluster.pgRepo.PruneExpiredA2ARecords(ctx, cutoff, cutoff, time.Time{})
		if err != nil {
			t.Fatalf("PruneExpiredA2ARecords failed: %v", err)
		}
		if prunedCount <= 0 {
			t.Fatalf("expected PruneExpiredA2ARecords to prune published stream/outbox records, got %d", prunedCount)
		}

		// 4. Scrape GET /metrics and verify all 11 gateway_a2a_* metrics are exported
		sc, _, rawMetrics := doLiveHTTP(t, http.MethodGet, cluster.ts1.URL+"/metrics", e2eMasterAdminKey, "", "", nil)
		if sc != http.StatusOK {
			t.Fatalf("GET /metrics failed (%d): %s", sc, string(rawMetrics))
		}
		metricsBody := string(rawMetrics)
		expectedMetrics := []string{
			"gateway_a2a_tasks_dispatched_total",
			"gateway_a2a_tasks_completed_total",
			"gateway_a2a_tasks_failed_total",
			"gateway_a2a_tasks_canceled_total",
			"gateway_a2a_upstream_http_json_total",
			"gateway_a2a_upstream_jsonrpc_total",
			"gateway_a2a_upstream_grpc_total",
			"gateway_a2a_active_stream_subscribers",
			"gateway_a2a_outbox_delivered_total",
			"gateway_a2a_outbox_dead_letter_total",
			"gateway_a2a_records_pruned_total",
		}
		for _, mName := range expectedMetrics {
			if !strings.Contains(metricsBody, mName) {
				t.Fatalf("expected Prometheus /metrics output to contain %q", mName)
			}
		}
	})
}
