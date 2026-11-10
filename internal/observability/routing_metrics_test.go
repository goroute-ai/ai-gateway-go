package observability

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
	"github.com/redis/go-redis/v9"
)

func TestCollector_RoutingSignalDegradedAndRedisCBStatePrometheus(t *testing.T) {
	mr := miniredis.RunT(t)
	fabric := storage.NewRedisFabric(mr.Addr(), "", 0)
	t.Cleanup(func() { _ = fabric.Client().Close() })

	col := NewCollector()
	col.SetRedisCBStateProvider(fabric.CBStateCode)

	col.RecordRoutingSignalDegraded()
	col.RecordRoutingSignalDegraded()

	// Trip the Redis fabric circuit breaker to open (2).
	mr.Close()
	for i := 0; i < 5; i++ {
		_, _ = fabric.Execute(func(rdb redis.UniversalClient) (any, error) {
			return nil, errors.New("redis unreachable")
		})
	}

	snap := col.Snapshot()
	if snap.RoutingSignalDegradedTotal != 2 {
		t.Fatalf("expected RoutingSignalDegradedTotal=2, got %d", snap.RoutingSignalDegradedTotal)
	}
	if snap.RedisCBState != 2 {
		t.Fatalf("expected RedisCBState=2 (open), got %d", snap.RedisCBState)
	}

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	col.PrometheusHandler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{
		"# TYPE gw_redis_cb_state gauge",
		"gw_redis_cb_state 2",
		"# TYPE gw_routing_signal_degraded_total counter",
		"gw_routing_signal_degraded_total 2",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected Prometheus output to contain %q, got:\n%s", want, body)
		}
	}

	// Direct SetRedisCBState works when no dynamic provider is set.
	col2 := NewCollector()
	col2.SetRedisCBState(1)
	col2.SetAdditionalMetricsProvider(func() map[string]float64 {
		return map[string]float64{"gw_redis_cb_state": 0}
	})
	rec2 := httptest.NewRecorder()
	col2.PrometheusHandler().ServeHTTP(rec2, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if count := strings.Count(rec2.Body.String(), "gw_redis_cb_state 1"); count != 1 {
		t.Fatalf("expected single gw_redis_cb_state 1 line, got %d in:\n%s", count, rec2.Body.String())
	}
}

func TestCollector_RoutingSignalDegradedConcurrent(t *testing.T) {
	col := NewCollector()
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 25; i++ {
				col.RecordRoutingSignalDegraded()
				_ = col.Snapshot()
			}
		}()
	}
	wg.Wait()
	if got := col.Snapshot().RoutingSignalDegradedTotal; got != 200 {
		t.Fatalf("expected 200 degraded signals, got %d", got)
	}
}
