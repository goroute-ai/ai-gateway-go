package observability

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
	"github.com/redis/go-redis/v9"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
)

func TestCollector_RoutingSignalDegradedAndRedisCBStateOTel(t *testing.T) {
	mr := miniredis.RunT(t)
	fabric := storage.NewRedisFabric(mr.Addr(), "", 0)
	t.Cleanup(func() { _ = fabric.Client().Close() })

	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	t.Cleanup(func() { _ = mp.Shutdown(context.Background()) })

	inst, err := NewInstruments(mp.Meter(instrumentationScopeName))
	if err != nil {
		t.Fatalf("NewInstruments: %v", err)
	}
	if err := inst.RegisterOperationalCallbacks(OperationalMetricsProviders{
		RedisCBState: fabric.CBStateCode,
	}); err != nil {
		t.Fatalf("RegisterOperationalCallbacks: %v", err)
	}

	col := NewCollector()
	col.SetInstruments(inst)
	col.SetRedisCBStateProvider(fabric.CBStateCode)

	col.RecordRoutingSignalDegraded()
	col.RecordRoutingSignalDegraded()

	// Trip the Redis fabric circuit breaker to open (2).
	mr.Close()
	for range 5 {
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

	metricsMap := collectMetricMap(t, reader)
	if got := gaugeInt64Value(t, metricsMap["gateway.redis.circuit_breaker.state"]); got != 2 {
		t.Fatalf("expected gateway.redis.circuit_breaker.state=2, got %d", got)
	}
	if got := sumInt64Value(t, metricsMap["gateway.routing.signal_degraded"]); got != 2 {
		t.Fatalf("expected gateway.routing.signal_degraded=2, got %d", got)
	}
}

func TestCollector_RoutingSignalDegradedConcurrent(t *testing.T) {
	col := NewCollector()
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 25 {
				col.RecordRoutingSignalDegraded()
				_ = col.Snapshot()
			}
		})
	}
	wg.Wait()
	if got := col.Snapshot().RoutingSignalDegradedTotal; got != 200 {
		t.Fatalf("expected 200 degraded signals, got %d", got)
	}
}
