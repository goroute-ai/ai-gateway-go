package observability

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCollectorSnapshotAndPrometheusExposition(t *testing.T) {
	col := NewCollector()

	col.RecordDeploymentAttempt("dep-bad", "primary-dead", "openai", "gpt-4.1-mini", 40, true)
	col.Record(RequestObservation{
		Provider:          "anthropic",
		Model:             "claude-haiku-4-5-20251001",
		DeploymentID:      "dep-ant",
		DeploymentName:    "anthropic-live",
		StatusCode:        200,
		LatencyMs:         650,
		TTFTMs:            220,
		RoutingMicros:     85,
		PromptTokens:      19,
		CompletionTokens:  7,
		CostMicros:        44,
		FallbackAttempted: true,
		RetryCount:        1,
	})
	col.Record(RequestObservation{
		Provider:         "gemini",
		Model:            "gemini-3.5-flash-lite",
		DeploymentID:     "dep-gem",
		DeploymentName:   "gemini-live",
		StatusCode:       200,
		LatencyMs:        420,
		TTFTMs:           150,
		RoutingMicros:    42,
		PromptTokens:     13,
		CompletionTokens: 2,
		CostMicros:       4,
	})
	col.Record(RequestObservation{
		Provider:   "gemini",
		Model:      "gemini-3.5-flash-lite",
		StatusCode: 200,
		CacheHit:   true,
	})
	col.Record(RequestObservation{
		StatusCode:  429,
		RateLimited: true,
	})
	col.Record(RequestObservation{
		StatusCode:       400,
		GuardrailBlocked: true,
	})

	snap := col.Snapshot()
	if snap.TotalRequests != 5 {
		t.Fatalf("expected 5 total requests, got %d", snap.TotalRequests)
	}
	if snap.TotalFallbacks != 1 {
		t.Fatalf("expected 1 fallback, got %d", snap.TotalFallbacks)
	}
	if snap.SlowestProvider != "anthropic" {
		t.Fatalf("expected slowest provider 'anthropic', got %q", snap.SlowestProvider)
	}
	if snap.HighestFailureDeployment != "primary-dead" {
		t.Fatalf("expected highest failure deployment 'primary-dead', got %q", snap.HighestFailureDeployment)
	}
	if snap.CacheHits != 1 || snap.RateLimitRejections != 1 || snap.GuardrailBlocks != 1 {
		t.Fatalf("unexpected cache/rl/guardrail counters: %+v", snap)
	}

	// Verify Prometheus /metrics exposition
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	col.PrometheusHandler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from /metrics, got %d", rec.Code)
	}
	body := rec.Body.String()
	for _, metric := range []string{
		"gateway_requests_total 5",
		"gateway_fallbacks_total 1",
		"gateway_cache_hits_total 1",
		"gateway_ratelimit_rejections_total 1",
		"gateway_guardrail_blocks_total 1",
	} {
		if !strings.Contains(body, metric) {
			t.Fatalf("expected Prometheus output to contain %q, got:\n%s", metric, body)
		}
	}

	// Verify W3C traceparent middleware
	handler := TraceMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tc := TraceFromContext(r.Context())
		if len(tc.TraceID) != 32 {
			t.Errorf("expected 32-char trace_id, got %q", tc.TraceID)
		}
		w.WriteHeader(http.StatusOK)
	}))
	tReq := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
	tReq.Header.Set("traceparent", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
	tRec := httptest.NewRecorder()
	handler.ServeHTTP(tRec, tReq)
	if got := tRec.Header().Get("X-Trace-Id"); got != "4bf92f3577b34da6a3ce929d0e0e4736" {
		t.Fatalf("expected propagated X-Trace-Id, got %q", got)
	}
}
