package drivers

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/guardrails"
	"github.com/goroute-ai/ai-gateway-go/internal/security/network"
	"github.com/stretchr/testify/require"
)

func makeDriverCfg(name, code string, extra map[string]any) guardrails.DriverConfig {
	cfgMap := map[string]any{
		"custom_code": code,
	}
	for k, v := range extra {
		cfgMap[k] = v
	}
	return guardrails.DriverConfig{
		Definition: &domain.GuardrailDefinition{
			ID:         "def-" + name,
			OrgID:      "org-test",
			Name:       name,
			Provider:   CustomCodeProvider,
			EventHooks: []domain.GuardrailHook{domain.GuardrailHookPreCall, domain.GuardrailHookPostCall},
			Status:     domain.GuardrailStatusActive,
			Config:     cfgMap,
		},
		EffectiveAction: domain.GuardrailActionBlock,
		EffectiveConfig: cfgMap,
	}
}

func TestCustomCodeVerdictsAndPlainDict(t *testing.T) {
	ctx := context.Background()

	t.Run("allow", func(t *testing.T) {
		drv, err := NewCustomCodeDriver(makeDriverCfg("allow-test", `
def apply_guardrail(inputs, request_data, input_type):
    if input_type == "request" and request_data["model"] == "fast":
        return allow()
    return block(reason="unexpected")
`, nil), nil)
		require.NoError(t, err)
		require.Equal(t, CustomCodeProvider, drv.Name())

		res, err := drv.Evaluate(ctx, &domain.GuardrailEvalInput{
			Direction: domain.GuardrailDirectionInput,
			Hook:      domain.GuardrailHookPreCall,
			Model:     "fast",
			Texts:     []string{"hello world"},
		})
		require.NoError(t, err)
		require.Equal(t, domain.GuardrailDecisionAllow, res.Decision)
		require.Empty(t, res.Violations)
	})

	t.Run("block_builder", func(t *testing.T) {
		drv, err := NewCustomCodeDriver(makeDriverCfg("block-test", `
def apply_guardrail(inputs, request_data, input_type):
    for text in inputs["texts"]:
        if contains(lower(text), "forbidden"):
            return block(reason="forbidden keyword found", category="policy", rule="no-forbidden", severity="high", score=0.99)
    return allow()
`, nil), nil)
		require.NoError(t, err)

		res, err := drv.Evaluate(ctx, &domain.GuardrailEvalInput{
			Texts: []string{"Please ignore FORBIDDEN phrase"},
		})
		require.NoError(t, err)
		require.Equal(t, domain.GuardrailDecisionBlock, res.Decision)
		require.Equal(t, "forbidden keyword found", res.ErrorMessage)
		require.Len(t, res.Violations, 1)
		require.Equal(t, "policy", res.Violations[0].Category)
		require.Equal(t, "no-forbidden", res.Violations[0].Rule)
		require.Equal(t, "high", res.Violations[0].Severity)
		require.NotNil(t, res.Violations[0].Score)
		require.InDelta(t, 0.99, *res.Violations[0].Score, 0.0001)
	})

	t.Run("flag_builder", func(t *testing.T) {
		drv, err := NewCustomCodeDriver(makeDriverCfg("flag-test", `
def apply_guardrail(inputs, request_data, input_type):
    return flag(reason="audit notice", category="compliance")
`, nil), nil)
		require.NoError(t, err)

		res, err := drv.Evaluate(ctx, &domain.GuardrailEvalInput{Texts: []string{"ok"}})
		require.NoError(t, err)
		require.Equal(t, domain.GuardrailDecisionFlag, res.Decision)
		require.Len(t, res.Violations, 1)
		require.Equal(t, domain.GuardrailActionAudit, res.Violations[0].Action)
		require.Equal(t, "audit notice", res.Violations[0].Message)
	})

	t.Run("plain_dict_verdict", func(t *testing.T) {
		drv, err := NewCustomCodeDriver(makeDriverCfg("plain-dict", `
def apply_guardrail(inputs, request_data, input_type):
    return {"action": "block", "reason": "blocked via plain dict", "rule": "dict-rule"}
`, nil), nil)
		require.NoError(t, err)

		res, err := drv.Evaluate(ctx, &domain.GuardrailEvalInput{Texts: []string{"test"}})
		require.NoError(t, err)
		require.Equal(t, domain.GuardrailDecisionBlock, res.Decision)
		require.Equal(t, "blocked via plain dict", res.ErrorMessage)
		require.Len(t, res.Violations, 1)
		require.Equal(t, "dict-rule", res.Violations[0].Rule)
	})

	t.Run("modify_texts_and_tool_calls", func(t *testing.T) {
		drv, err := NewCustomCodeDriver(makeDriverCfg("modify-test", `
def apply_guardrail(inputs, request_data, input_type):
    new_texts = [regex_replace(t, "\\b\\d{3}-\\d{2}-\\d{4}\\b", "[SSN_REDACTED]") for t in inputs["texts"]]
    new_calls = []
    for tc in inputs["tool_calls"]:
        args = json_parse(tc["function"]["arguments"])
        if "token" in args:
            args["token"] = "[REDACTED]"
        new_calls.append({
            "id": tc["id"],
            "type": tc["type"],
            "function": {
                "name": tc["function"]["name"],
                "arguments": json_dumps(args),
            },
        })
    return modify(texts=new_texts, tool_calls=new_calls, reason="redacted sensitive fields")
`, nil), nil)
		require.NoError(t, err)

		res, err := drv.Evaluate(ctx, &domain.GuardrailEvalInput{
			Texts: []string{"My SSN is 123-45-6789."},
			ToolCalls: []domain.CanonicalToolCall{{
				ID:   "call_1",
				Type: "function",
				Function: domain.CanonicalFunctionCall{
					Name:      "fetch_profile",
					Arguments: `{"user":"alice","token":"secret-tok"}`,
				},
			}},
		})
		require.NoError(t, err)
		require.Equal(t, domain.GuardrailDecisionModify, res.Decision)
		require.Equal(t, []string{"My SSN is [SSN_REDACTED]."}, res.ModifiedTexts)
		require.Len(t, res.ModifiedToolCalls, 1)
		require.Equal(t, "call_1", res.ModifiedToolCalls[0].ID)
		require.Equal(t, "fetch_profile", res.ModifiedToolCalls[0].Function.Name)
		var decodedArgs map[string]any
		require.NoError(t, json.Unmarshal([]byte(res.ModifiedToolCalls[0].Function.Arguments), &decodedArgs))
		require.Equal(t, "[REDACTED]", decodedArgs["token"])
		require.Equal(t, "alice", decodedArgs["user"])
	})
}

func TestCustomCodeHelpersAndInputEnvelope(t *testing.T) {
	ctx := context.Background()

	drv, err := NewCustomCodeDriver(makeDriverCfg("helpers-test", `
def apply_guardrail(inputs, request_data, input_type):
    txt = inputs["texts"][0]
    matched = regex_match(txt, "sk-[a-zA-Z0-9]+")
    found = regex_findall(txt, "sk-[a-zA-Z0-9]+")
    searched = regex_search(txt, "sk-[a-zA-Z0-9]+")
    replaced = regex_replace(txt, "sk-[a-zA-Z0-9]+", "[KEY]")
    digest = sha256("hello")
    parsed = json_parse('{"k": 42, "tags": ["a", "b"]}')
    dumped = json_dumps({"ok": True, "n": parsed["k"]})

    # Verify request_data and input_type propagation and header sanitization.
    if input_type != "mcp_call":
        return block(reason="expected mcp_call input_type")
    if request_data["org_id"] != "org-1" or request_data["team_id"] != "team-1":
        return block(reason="missing tenant metadata")
    if request_data["virtual_key_id"] != "vk-1" or request_data["end_user_id"] != "user-1":
        return block(reason="missing caller metadata")
    if "authorization" in request_data["request_headers"] or "Authorization" in request_data["request_headers"]:
        return block(reason="sensitive authorization header leaked")
    if request_data["request_headers"].get("X-Tenant-Env") != "prod":
        return block(reason="missing safe header")
    if len(inputs["images"]) != 1 or len(inputs["tools"]) != 1 or len(inputs["structured_messages"]) != 1:
        return block(reason="missing structured inputs")

    if not matched or len(found) != 2 or searched != "sk-abc123":
        return block(reason="regex helpers mismatch")
    if digest != "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824":
        return block(reason="sha256 mismatch: " + digest)
    if not contains(dumped, "42") or not contains(request_data["tags"], "vip"):
        return block(reason="json/contains mismatch")

    return modify(texts=[replaced])
`, nil), nil)
	require.NoError(t, err)

	res, err := drv.Evaluate(ctx, &domain.GuardrailEvalInput{
		Direction:    domain.GuardrailDirectionInput,
		Hook:         domain.GuardrailHookPreMCPCall,
		OrgID:        "org-1",
		TeamID:       "team-1",
		VirtualKeyID: "vk-1",
		EndUserID:    "user-1",
		Model:        "fast",
		Tags:         []string{"vip"},
		Metadata:     map[string]any{"task": "t1"},
		RequestHeaders: map[string]string{
			"Authorization": "Bearer super-secret",
			"X-Tenant-Env":  "prod",
		},
		Texts: []string{"keys: sk-abc123 and sk-xyz999"},
		StructuredMessages: []domain.CanonicalMessage{{
			Role:    "user",
			Content: "keys: sk-abc123 and sk-xyz999",
		}},
		Images: []domain.ImageURL{{URL: "https://example.com/img.png"}},
		Tools:  []domain.CanonicalTool{{Type: "function", Function: domain.CanonicalFunction{Name: "search"}}},
	})
	require.NoError(t, err)
	require.Equal(t, domain.GuardrailDecisionModify, res.Decision)
	require.Equal(t, []string{"keys: [KEY] and [KEY]"}, res.ModifiedTexts)

	// Invalid regex must fail gracefully without panicking.
	badRegexDrv, err := NewCustomCodeDriver(makeDriverCfg("bad-regex", `
def apply_guardrail(inputs, request_data, input_type):
    return allow() if regex_match(inputs["texts"][0], "[unclosed") else block()
`, nil), nil)
	require.NoError(t, err)
	_, err = badRegexDrv.Evaluate(ctx, &domain.GuardrailEvalInput{Texts: []string{"hello"}})
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid regex pattern")
}

func TestCustomCodeHTTPAndStrictSSRF(t *testing.T) {
	ctx := context.Background()

	t.Run("http_get_and_http_post_allowed_client", func(t *testing.T) {
		var sawAuthHeader string
		var sawMethod string
		var sawPayload map[string]any

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sawMethod = r.Method
			sawAuthHeader = r.Header.Get("X-Guardrail-Token")
			if r.Method == http.MethodPost {
				body, _ := io.ReadAll(r.Body)
				_ = json.Unmarshal(body, &sawPayload)
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"verdict": "block",
				"reason":  "remote policy denied",
			})
		}))
		defer srv.Close()

		// Explicitly injected test HTTP client for local httptest server.
		drv, err := NewCustomCodeDriver(makeDriverCfg("http-allowed", `
def apply_guardrail(inputs, request_data, input_type):
    get_resp = http_get("`+srv.URL+`/health", headers={"X-Guardrail-Token": "tok-get"})
    if not get_resp["ok"]:
        return block(reason="healthcheck failed")
    post_resp = http_post("`+srv.URL+`/check", json={"text": inputs["texts"][0]}, headers={"X-Guardrail-Token": "tok-post"})
    if post_resp["json"]["verdict"] == "block":
        return block(reason=post_resp["json"]["reason"])
    return allow()
`, map[string]any{"execution_timeout_ms": 2000}), srv.Client())
		require.NoError(t, err)

		res, err := drv.Evaluate(ctx, &domain.GuardrailEvalInput{Texts: []string{"check me"}})
		require.NoError(t, err)
		require.Equal(t, domain.GuardrailDecisionBlock, res.Decision)
		require.Equal(t, "remote policy denied", res.ErrorMessage)
		require.Equal(t, http.MethodPost, sawMethod)
		require.Equal(t, "tok-post", sawAuthHeader)
		require.Equal(t, "check me", sawPayload["text"])
	})

	t.Run("strict_ssrf_blocks_loopback_and_metadata", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer srv.Close()

		// Nil httpClient uses strict network.NewHTTPClient policy (blocks loopback, private, metadata, http://).
		loopbackDrv, err := NewCustomCodeDriver(makeDriverCfg("ssrf-loopback", `
def apply_guardrail(inputs, request_data, input_type):
    resp = http_get("`+strings.Replace(srv.URL, "http://", "https://", 1)+`")
    return allow()
`, nil), nil)
		require.NoError(t, err)

		_, err = loopbackDrv.Evaluate(ctx, &domain.GuardrailEvalInput{Texts: []string{"hello"}})
		require.Error(t, err)
		require.ErrorIs(t, err, network.ErrPrivateNetworkBlocked)

		metadataDrv, err := NewCustomCodeDriver(makeDriverCfg("ssrf-metadata", `
def apply_guardrail(inputs, request_data, input_type):
    resp = http_post("https://169.254.169.254/latest/meta-data/", json={"a": 1})
    return allow()
`, nil), nil)
		require.NoError(t, err)

		_, err = metadataDrv.Evaluate(ctx, &domain.GuardrailEvalInput{Texts: []string{"hello"}})
		require.Error(t, err)
		require.ErrorIs(t, err, network.ErrCloudMetadataBlocked)

		insecureHTTPDrv, err := NewCustomCodeDriver(makeDriverCfg("ssrf-http", `
def apply_guardrail(inputs, request_data, input_type):
    resp = http_get("`+srv.URL+`")
    return allow()
`, nil), nil)
		require.NoError(t, err)

		_, err = insecureHTTPDrv.Evaluate(ctx, &domain.GuardrailEvalInput{Texts: []string{"hello"}})
		require.Error(t, err)
		require.ErrorIs(t, err, network.ErrInsecureHTTPBlocked)
	})

	t.Run("bounded_http_response_size", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(strings.Repeat("x", int(maxHTTPResponseBytes)+64)))
		}))
		defer srv.Close()

		drv, err := NewCustomCodeDriver(makeDriverCfg("http-oversize", `
def apply_guardrail(inputs, request_data, input_type):
    resp = http_get("`+srv.URL+`")
    return allow()
`, map[string]any{"execution_timeout_ms": 2000}), srv.Client())
		require.NoError(t, err)

		_, err = drv.Evaluate(ctx, &domain.GuardrailEvalInput{Texts: []string{"hello"}})
		require.Error(t, err)
		require.Contains(t, err.Error(), "exceeds")
	})
}

func TestCustomCodeResourceBoundsAndNoGoroutineLeak(t *testing.T) {
	t.Run("step_limit_stops_runaway_loop", func(t *testing.T) {
		drv, err := NewCustomCodeDriver(makeDriverCfg("step-limit", `
def apply_guardrail(inputs, request_data, input_type):
    total = 0
    for i in range(1000000):
        total += i
    return allow()
`, map[string]any{
			"max_execution_steps":  2000,
			"execution_timeout_ms": 2000,
		}), nil)
		require.NoError(t, err)

		_, err = drv.Evaluate(context.Background(), &domain.GuardrailEvalInput{Texts: []string{"hi"}})
		require.Error(t, err)
		require.Contains(t, strings.ToLower(err.Error()), "step")
	})

	t.Run("ctx_timeout_cancels_slow_execution_without_goroutine_leak", func(t *testing.T) {
		releaseServer := make(chan struct{})
		defer close(releaseServer)

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			select {
			case <-r.Context().Done():
			case <-releaseServer:
			}
		}))
		defer srv.Close()

		drv, err := NewCustomCodeDriver(makeDriverCfg("timeout-cancel", `
def apply_guardrail(inputs, request_data, input_type):
    http_get("`+srv.URL+`/slow")
    return allow()
`, map[string]any{
			"execution_timeout_ms": 50,
		}), srv.Client())
		require.NoError(t, err)

		baseline := runtime.NumGoroutine()
		for i := 0; i < 5; i++ {
			ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
			_, evalErr := drv.Evaluate(ctx, &domain.GuardrailEvalInput{Texts: []string{"slow"}})
			cancel()
			require.Error(t, evalErr)
			require.True(t, errors.Is(evalErr, context.DeadlineExceeded) || strings.Contains(evalErr.Error(), "deadline"))
		}

		// Allow httptest handler goroutines to settle and verify no watcher goroutines leaked.
		require.Eventually(t, func() bool {
			runtime.GC()
			return runtime.NumGoroutine() <= baseline+2
		}, 2*time.Second, 20*time.Millisecond)
	})
}

func TestCustomCodeSandboxIsolationAndSignatureValidation(t *testing.T) {
	cases := []struct {
		name string
		code string
		want string
	}{
		{
			name: "forbid_load",
			code: `
load("//evil.star", "evil")
def apply_guardrail(inputs, request_data, input_type):
    return allow()
`,
			want: "load()",
		},
		{
			name: "forbid_while",
			code: `
def apply_guardrail(inputs, request_data, input_type):
    while True:
        pass
    return allow()
`,
			want: "while",
		},
		{
			name: "forbid_undefined_open",
			code: `
def apply_guardrail(inputs, request_data, input_type):
    open("/etc/passwd")
    return allow()
`,
			want: "undefined: open",
		},
		{
			name: "forbid_undefined_os",
			code: `
def apply_guardrail(inputs, request_data, input_type):
    return block(reason=os.getenv("SECRET"))
`,
			want: "undefined: os",
		},
		{
			name: "missing_apply_guardrail",
			code: `
def other_fn(a, b, c):
    return allow()
`,
			want: "must define apply_guardrail",
		},
		{
			name: "wrong_arity_too_few",
			code: `
def apply_guardrail(inputs):
    return allow()
`,
			want: "must accept 3 parameters",
		},
		{
			name: "wrong_arity_too_many_required",
			code: `
def apply_guardrail(a, b, c, d):
    return allow()
`,
			want: "at most 3 required positional parameters",
		},
		{
			name: "empty_code",
			code: `   `,
			want: "must not be empty",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewCustomCodeDriver(makeDriverCfg(tc.name, tc.code, nil), nil)
			require.Error(t, err)
			require.Contains(t, err.Error(), tc.want)
		})
	}
}

func TestCustomCodeConcurrentEvaluate(t *testing.T) {
	drv, err := NewCustomCodeDriver(makeDriverCfg("concurrent", `
def apply_guardrail(inputs, request_data, input_type):
    txt = inputs["texts"][0]
    if contains(txt, "bad"):
        return block(reason="bad:" + request_data["request_id"])
    return modify(texts=[lower(txt)])
`, nil), nil)
	require.NoError(t, err)

	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			reqID := "req-" + string(rune('a'+idx))
			if idx%2 == 0 {
				res, evalErr := drv.Evaluate(context.Background(), &domain.GuardrailEvalInput{
					RequestID: reqID,
					Texts:     []string{"bad input"},
				})
				require.NoError(t, evalErr)
				require.Equal(t, domain.GuardrailDecisionBlock, res.Decision)
				require.Equal(t, "bad:"+reqID, res.ErrorMessage)
			} else {
				res, evalErr := drv.Evaluate(context.Background(), &domain.GuardrailEvalInput{
					RequestID: reqID,
					Texts:     []string{"HELLO WORLD"},
				})
				require.NoError(t, evalErr)
				require.Equal(t, domain.GuardrailDecisionModify, res.Decision)
				require.Equal(t, []string{"hello world"}, res.ModifiedTexts)
			}
		}(i)
	}
	wg.Wait()
}
