package guardrails_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/mcp"
	"github.com/goroute-ai/ai-gateway-go/internal/server"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
	"github.com/stretchr/testify/require"
)

const testAdminKey = "sk-gw-guardrail-lab-admin-key"

// guardrailLab encapsulates an isolated, zero-external-dependency GoRoute test setup
// (MemoryRepository + miniredis + GatewayServer + mock upstreams) tailored for testing guardrails.
type guardrailLab struct {
	t            *testing.T
	cfg          *config.Config
	repo         *storage.MemoryRepository
	gw           *server.GatewayServer
	srv          *httptest.Server
	upstream     *httptest.Server
	orgID        string
	teamID       string
	adminHeaders map[string]string
	authHeaders  map[string]string
	mu           sync.Mutex
	capturedReq  []capturedUpstreamCall
}

type capturedUpstreamCall struct {
	Method string
	Path   string
	Body   string
}

type labConfig struct {
	guardrailsCfg  config.GuardrailsConfig
	allowPrivate   bool
	allowHTTP      bool
	enableCache    bool
	enableMCP      bool
	enableA2A      bool
	streamChunks   []string
	nonStreamReply string
}

type labOption func(*labConfig)

func withGuardrailsConfig(gcfg config.GuardrailsConfig) labOption {
	return func(c *labConfig) { c.guardrailsCfg = gcfg }
}

func withResponseCache() labOption {
	return func(c *labConfig) { c.enableCache = true }
}

func withMCPAndA2A() labOption {
	return func(c *labConfig) {
		c.enableMCP = true
		c.enableA2A = true
	}
}

func withStreamChunks(chunks ...string) labOption {
	return func(c *labConfig) { c.streamChunks = chunks }
}

func withNonStreamReply(reply string) labOption {
	return func(c *labConfig) { c.nonStreamReply = reply }
}

func newGuardrailLab(t *testing.T, opts ...labOption) *guardrailLab {
	t.Helper()

	lc := &labConfig{
		allowPrivate:   true,
		allowHTTP:      true,
		streamChunks:   []string{"Hello from mock stream."},
		nonStreamReply: "Hello from mock upstream.",
	}
	for _, opt := range opts {
		opt(lc)
	}

	lab := &guardrailLab{
		t:            t,
		repo:         storage.NewMemoryRepository(),
		adminHeaders: map[string]string{"Authorization": "Bearer " + testAdminKey},
	}

	lab.upstream = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rawBody, _ := io.ReadAll(r.Body)
		lab.mu.Lock()
		lab.capturedReq = append(lab.capturedReq, capturedUpstreamCall{
			Method: r.Method,
			Path:   r.URL.Path,
			Body:   string(rawBody),
		})
		chunks := append([]string(nil), lc.streamChunks...)
		reply := lc.nonStreamReply
		lab.mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/chat/completions"):
			var reqBody struct {
				Stream bool `json:"stream"`
			}
			_ = json.Unmarshal(rawBody, &reqBody)
			if reqBody.Stream {
				w.Header().Set("Content-Type", "text/event-stream")
				for i, c := range chunks {
					delta := map[string]any{"content": c}
					if i == 0 {
						delta["role"] = "assistant"
					}
					choice := map[string]any{"index": 0, "delta": delta}
					ev := map[string]any{
						"id":      "chatcmpl-lab-stream",
						"object":  "chat.completion.chunk",
						"model":   "llama-3.1-8b-instant",
						"choices": []map[string]any{choice},
					}
					if i == len(chunks)-1 {
						choice["finish_reason"] = "stop"
						ev["usage"] = map[string]any{
							"prompt_tokens":     6,
							"completion_tokens": 12,
							"total_tokens":      18,
						}
					}
					b, _ := json.Marshal(ev)
					fmt.Fprintf(w, "data: %s\n\n", string(b))
				}
				fmt.Fprint(w, "data: [DONE]\n\n")
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id":     "chatcmpl-lab-1",
				"object": "chat.completion",
				"model":  "llama-3.1-8b-instant",
				"choices": []map[string]any{{
					"index": 0,
					"message": map[string]any{
						"role":    "assistant",
						"content": reply,
					},
					"finish_reason": "stop",
				}},
				"usage": map[string]any{
					"prompt_tokens":     5,
					"completion_tokens": 9,
					"total_tokens":      14,
				},
			})

		case strings.HasSuffix(r.URL.Path, "/embeddings"):
			_ = json.NewEncoder(w).Encode(map[string]any{
				"object": "list",
				"data": []map[string]any{{
					"object":    "embedding",
					"index":     0,
					"embedding": []float64{0.1, 0.2, 0.3},
				}},
				"model": "text-embedding-3-small",
				"usage": map[string]any{"prompt_tokens": 4, "total_tokens": 4},
			})

		case strings.HasSuffix(r.URL.Path, "/moderations"):
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id":    "modr-lab-1",
				"model": "omni-moderation-latest",
				"results": []map[string]any{{
					"flagged":         false,
					"categories":      map[string]bool{"hate": false},
					"category_scores": map[string]float64{"hate": 0.01},
				}},
			})

		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(lab.upstream.Close)

	mr := miniredis.RunT(t)
	redisFabric := storage.NewRedisFabric(mr.Addr(), "", 0)
	t.Cleanup(func() { _ = redisFabric.Client().Close() })

	cfg := config.Default()
	cfg.Auth.MasterAdminKey = testAdminKey
	cfg.Security.Network.OutboundSSRF.AllowPrivateNetworks = lc.allowPrivate
	cfg.Security.Network.OutboundSSRF.AllowInsecureHTTP = lc.allowHTTP
	cfg.Guardrails = lc.guardrailsCfg
	if lc.enableCache {
		cfg.Cache.Enabled = true
	}
	if lc.enableMCP {
		cfg.MCP.Enabled = true
	}
	if lc.enableA2A {
		cfg.A2A.Enabled = true
	}
	lab.cfg = cfg

	gw, err := server.New(cfg, lab.repo, redisFabric, nil)
	require.NoError(t, err)

	ctx := context.Background()
	gw.StartWorkers(ctx)
	t.Cleanup(func() { gw.Shutdown(context.Background()) })

	lab.gw = gw
	lab.srv = httptest.NewServer(gw.Handler())
	t.Cleanup(lab.srv.Close)

	lab.provisionDefaultTenant(t)
	return lab
}

func (l *guardrailLab) provisionDefaultTenant(t *testing.T) {
	t.Helper()
	ctx := context.Background()

	var org domain.Organization
	resp, raw := l.doJSON(http.MethodPost, "/admin/v1/organizations", l.adminHeaders, map[string]any{
		"name": "Guardrails Lab Org",
		"slug": "guardrails-lab-org",
	}, &org)
	require.Equal(t, http.StatusCreated, resp.StatusCode, "create org: %s", string(raw))
	l.orgID = org.ID

	// Enable groq and openai so all endpoint tests route through one tenant.
	for _, prov := range []string{"groq", "openai"} {
		r, body := l.doJSON(http.MethodPost, "/admin/v1/organizations/"+l.orgID+"/subscriptions", l.adminHeaders, map[string]any{
			"provider": prov, "is_enabled": true,
		}, nil)
		require.Equal(t, http.StatusOK, r.StatusCode, "enable %s: %s", prov, string(body))
	}

	// Register GlobalModels for utility modalities (embeddings, moderations).
	extraModels := []*domain.GlobalModel{
		{
			ID:                "openai/text-embedding-3-small",
			Provider:          domain.ProviderOpenAI,
			ModelName:         "text-embedding-3-small",
			DisplayName:       "OpenAI Embedding Small",
			SupportsInference: true,
			LifecycleStatus:   domain.ModelStatusActive,
			PricingStatus:     domain.PricingStatusVerified,
			Capabilities:      domain.ModelCapabilities{Embeddings: domain.CapabilitySupported},
		},
		{
			ID:                "openai/omni-moderation-latest",
			Provider:          domain.ProviderOpenAI,
			ModelName:         "omni-moderation-latest",
			DisplayName:       "Omni Moderation Latest",
			SupportsInference: true,
			LifecycleStatus:   domain.ModelStatusActive,
			PricingStatus:     domain.PricingStatusVerified,
			Capabilities:      domain.ModelCapabilities{Moderation: domain.CapabilitySupported},
		},
	}
	for _, gm := range extraModels {
		require.NoError(t, l.repo.UpsertGlobalModel(ctx, gm))
	}

	// Credentials + model groups + deployments for fast (groq), emb, modr.
	credIDs := map[string]string{}
	for _, spec := range []struct{ prov, name, key string }{
		{"groq", "mock-groq", "gsk_MockLabKey"},
		{"openai", "mock-openai", "sk-mock-openai-lab-key"},
	} {
		var cred domain.ProviderCredential
		r, b := l.doJSON(http.MethodPost, "/admin/v1/credentials", l.adminHeaders, map[string]any{
			"org_id": l.orgID, "provider": spec.prov, "name": spec.name,
			"base_url": l.upstream.URL, "api_key": spec.key,
		}, &cred)
		require.Equal(t, http.StatusCreated, r.StatusCode, "credential %s: %s", spec.prov, string(b))
		credIDs[spec.prov] = cred.ID
	}

	for _, mg := range []struct{ alias, globalModel, prov string }{
		{"fast", "groq/llama-3.1-8b-instant", "groq"},
		{"emb-small", "openai/text-embedding-3-small", "openai"},
		{"modr", "openai/omni-moderation-latest", "openai"},
	} {
		var grp domain.ModelGroup
		r, b := l.doJSON(http.MethodPost, "/admin/v1/model-groups", l.adminHeaders, map[string]any{
			"org_id": l.orgID, "alias": mg.alias, "routing_strategy": "weighted-shuffle",
		}, &grp)
		require.Equal(t, http.StatusCreated, r.StatusCode, "model-group %s: %s", mg.alias, string(b))

		r, b = l.doJSON(http.MethodPost, "/admin/v1/deployments", l.adminHeaders, map[string]any{
			"model_group_id": grp.ID, "global_model_id": mg.globalModel,
			"credential_id": credIDs[mg.prov], "deployment_name": mg.alias + "-dep", "weight": 100,
		}, nil)
		require.Equal(t, http.StatusCreated, r.StatusCode, "deployment %s: %s", mg.alias, string(b))
	}

	var team domain.Team
	r, b := l.doJSON(http.MethodPost, "/admin/v1/teams", l.adminHeaders, map[string]any{
		"org_id": l.orgID, "name": "Guardrails Team",
	}, &team)
	require.Equal(t, http.StatusCreated, r.StatusCode, "team: %s", string(b))
	l.teamID = team.ID

	var keyResp struct {
		Key string `json:"raw_key"`
	}
	r, b = l.doJSON(http.MethodPost, "/admin/v1/keys", l.adminHeaders, map[string]any{
		"org_id":              l.orgID,
		"team_id":             l.teamID,
		"name":                "guardrails-lab-key",
		"allowed_models":      []string{"fast", "emb-small", "modr"},
		"allowed_mcp_servers": []string{"*"},
		"allowed_a2a_agents":  []string{"*"},
	}, &keyResp)
	require.Equal(t, http.StatusCreated, r.StatusCode, "issue key: %s", string(b))
	require.NotEmpty(t, keyResp.Key)
	l.authHeaders = map[string]string{"Authorization": "Bearer " + keyResp.Key}
}

func (l *guardrailLab) setPolicy(t *testing.T, policy any) domain.GuardrailPolicy {
	t.Helper()
	var saved domain.GuardrailPolicy
	resp, raw := l.doJSON(http.MethodPost, "/admin/v1/organizations/"+l.orgID+"/guardrails", l.adminHeaders, policy, &saved)
	require.Equal(t, http.StatusOK, resp.StatusCode, "set guardrail policy: %s", string(raw))
	return saved
}

func (l *guardrailLab) getPolicy(t *testing.T) domain.GuardrailPolicy {
	t.Helper()
	var pol domain.GuardrailPolicy
	resp, raw := l.doJSON(http.MethodGet, "/admin/v1/organizations/"+l.orgID+"/guardrails", l.adminHeaders, nil, &pol)
	require.Equal(t, http.StatusOK, resp.StatusCode, "get guardrail policy: %s", string(raw))
	return pol
}

func (l *guardrailLab) simulate(t *testing.T, payload any) (int, map[string]any) {
	t.Helper()
	var out map[string]any
	resp, _ := l.doJSON(http.MethodPost, "/admin/v1/organizations/"+l.orgID+"/guardrails/simulate", l.adminHeaders, payload, &out)
	return resp.StatusCode, out
}

func (l *guardrailLab) doJSON(method, path string, headers map[string]string, body any, out any) (*http.Response, []byte) {
	l.t.Helper()
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		require.NoError(l.t, err)
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, l.srv.URL+path, rdr)
	require.NoError(l.t, err)
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	require.NoError(l.t, err)
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	require.NoError(l.t, err)
	if out != nil && len(raw) > 0 {
		_ = json.Unmarshal(raw, out)
	}
	return resp, raw
}

func (l *guardrailLab) upstreamCalls() []capturedUpstreamCall {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]capturedUpstreamCall, len(l.capturedReq))
	copy(out, l.capturedReq)
	return out
}

func (l *guardrailLab) clearUpstreamCalls() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.capturedReq = nil
}

// webhookScanRecord captures what the generic_http driver sends on the wire.
type webhookScanRecord struct {
	OrgID     string            `json:"org_id"`
	InputType string            `json:"input_type"`
	Hook      string            `json:"hook"`
	Texts     []string          `json:"texts"`
	Headers   map[string]string `json:"-"`
}

type mockWebhookScanner struct {
	srv     *httptest.Server
	mu      sync.Mutex
	records []webhookScanRecord
}

func newMockWebhookScanner(t *testing.T, fn func(rec webhookScanRecord) (status int, decision string, violations []string)) *mockWebhookScanner {
	t.Helper()
	m := &mockWebhookScanner{}
	m.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var rec webhookScanRecord
		_ = json.NewDecoder(r.Body).Decode(&rec)
		rec.Headers = map[string]string{
			"Authorization": r.Header.Get("Authorization"),
			"X-Scanner-Key": r.Header.Get("X-Scanner-Key"),
		}
		m.mu.Lock()
		m.records = append(m.records, rec)
		m.mu.Unlock()

		status, decision, violations := fn(rec)
		if status == 0 {
			status = http.StatusOK
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"decision":   decision,
			"violations": violations,
		})
	}))
	t.Cleanup(m.srv.Close)
	return m
}

func (m *mockWebhookScanner) calls() []webhookScanRecord {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]webhookScanRecord, len(m.records))
	copy(out, m.records)
	return out
}

// buildMCPUpstreamMock creates a JSON-RPC MCP server returning given tools & handling tools/call.
func buildMCPUpstreamMock(t *testing.T, tools []map[string]any, callFn func(name string, args map[string]any) (any, error)) (*httptest.Server, *int) {
	t.Helper()
	var callCount int
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req mcp.JSONRPCRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		w.Header().Set("Content-Type", "application/json")

		switch req.Method {
		case "tools/list":
			_ = json.NewEncoder(w).Encode(mcp.JSONRPCResponse{
				JSONRPC: "2.0",
				ID:      req.ID,
				Result:  map[string]any{"tools": tools},
			})
		case "tools/call":
			mu.Lock()
			callCount++
			mu.Unlock()
			var p struct {
				Name      string         `json:"name"`
				Arguments map[string]any `json:"arguments"`
			}
			_ = json.Unmarshal(req.Params, &p)
			res, err := callFn(p.Name, p.Arguments)
			if err != nil {
				_ = json.NewEncoder(w).Encode(mcp.JSONRPCResponse{
					JSONRPC: "2.0",
					ID:      req.ID,
					Error:   &mcp.JSONRPCError{Code: -32000, Message: err.Error()},
				})
				return
			}
			_ = json.NewEncoder(w).Encode(mcp.JSONRPCResponse{
				JSONRPC: "2.0",
				ID:      req.ID,
				Result:  res,
			})
		default:
			_ = json.NewEncoder(w).Encode(mcp.JSONRPCResponse{
				JSONRPC: "2.0",
				ID:      req.ID,
				Error:   &mcp.JSONRPCError{Code: mcp.CodeMethodNotFound, Message: "unsupported method"},
			})
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &callCount
}
