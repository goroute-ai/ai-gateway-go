package router

import (
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
)

func TestLoadBalancer_SharedAdaptiveSignalsAcrossInstancesAndExpire(t *testing.T) {
	server := miniredis.RunT(t)
	redisA := storage.NewRedisFabric(server.Addr(), "", 0)
	redisB := storage.NewRedisFabric(server.Addr(), "", 0)
	defer redisA.Client().Close()
	defer redisB.Client().Close()
	lbA := NewLoadBalancer(redisA)
	lbB := NewLoadBalancer(redisB)
	depA := &domain.Deployment{ID: "dep-a", TPMCapacity: 1000}
	depB := &domain.Deployment{ID: "dep-b", TPMCapacity: 1000}
	candidates := []*domain.Deployment{depA, depB}

	lbA.OnRequestStart(depA.ID)
	if selected := lbB.Select(domain.StrategyLeastBusy, candidates); selected.ID != depB.ID {
		t.Fatalf("least-busy ignored replica A's in-flight request: selected %s", selected.ID)
	}
	lbA.OnRequestEnd(depA.ID, 10, 950)
	if selected := lbB.Select(domain.StrategyUsageBasedHeadroom, candidates); selected.ID != depB.ID {
		t.Fatalf("headroom strategy ignored replica A's token usage: selected %s", selected.ID)
	}
	if selected := lbB.Select(domain.StrategyLatencyBased, candidates); selected.ID != depA.ID {
		t.Fatalf("latency strategy ignored replica A's EWMA: selected %s", selected.ID)
	}
	if !lbB.SharedSignalsAvailable() {
		t.Fatal("shared signals should be reported available after successful reads")
	}

	server.FastForward(11 * time.Minute)
	for _, key := range server.Keys() {
		if len(key) >= len("gw:routing:signals:") && key[:len("gw:routing:signals:")] == "gw:routing:signals:" {
			t.Fatalf("routing signal key survived TTL: %s", key)
		}
	}
}

func TestLoadBalancer_RedisFailureFallsBackToLocalAndReportsDegraded(t *testing.T) {
	server := miniredis.RunT(t)
	redis := storage.NewRedisFabric(server.Addr(), "", 0)
	defer redis.Client().Close()
	lb := NewLoadBalancer(redis)
	depA := &domain.Deployment{ID: "dep-a"}
	depB := &domain.Deployment{ID: "dep-b"}
	candidates := []*domain.Deployment{depA, depB}

	lb.OnRequestStart(depA.ID)
	server.Close()
	if selected := lb.Select(domain.StrategyLeastBusy, candidates); selected.ID != depB.ID {
		t.Fatalf("expected process-local fallback to use local in-flight state, got %s", selected.ID)
	}
	if lb.SharedSignalsAvailable() {
		t.Fatal("shared signal status must report degraded after Redis failure")
	}

	if err := server.Restart(); err != nil {
		t.Fatalf("restart Redis: %v", err)
	}
	if selected := lb.Select(domain.StrategyLeastBusy, candidates); selected.ID != depB.ID {
		t.Fatalf("expected recovered shared signal read to retain observation, got %s", selected.ID)
	}
	if !lb.SharedSignalsAvailable() {
		t.Fatal("shared signal status should recover after successful Redis read")
	}
}
