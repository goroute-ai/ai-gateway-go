package router

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
)

func TestCircuitProbeLeaseIsSharedAcrossManagersAndRecoveryClearsState(t *testing.T) {
	ctx := context.Background()
	redisServer := miniredis.RunT(t)
	newManager := func() *ReliabilityManager {
		return NewReliabilityManager(nil, nil, nil, nil, nil, nil, storage.NewRedisFabric(redisServer.Addr(), "", 0), config.RouterConfig{})
	}
	first := newManager()
	second := newManager()
	const deploymentID = "shared-probe"

	first.tripCooldown(ctx, deploymentID, 1)
	if first.GetCircuitState(ctx, deploymentID) != CircuitOpen || second.GetCircuitState(ctx, deploymentID) != CircuitOpen {
		t.Fatal("expected both managers to observe the shared open circuit")
	}
	redisServer.FastForward(time.Second)
	if first.GetCircuitState(ctx, deploymentID) != CircuitHalfOpen || second.GetCircuitState(ctx, deploymentID) != CircuitHalfOpen {
		t.Fatal("expected both managers to observe half-open after cooldown expiry")
	}

	start := make(chan struct{})
	results := make(chan struct {
		manager *ReliabilityManager
		allowed bool
		token   string
	}, 2)
	var wg sync.WaitGroup
	for _, manager := range []*ReliabilityManager{first, second} {
		wg.Add(1)
		go func(manager *ReliabilityManager) {
			defer wg.Done()
			<-start
			allowed, token := manager.allowDeploymentRequest(ctx, deploymentID)
			results <- struct {
				manager *ReliabilityManager
				allowed bool
				token   string
			}{manager: manager, allowed: allowed, token: token}
		}(manager)
	}
	close(start)
	wg.Wait()
	close(results)
	allowed := 0
	var probeManager *ReliabilityManager
	var probe *domain.Deployment
	for result := range results {
		if result.allowed {
			allowed++
			probeManager = result.manager
			probe = &domain.Deployment{ID: deploymentID, CircuitProbeToken: result.token}
		}
	}
	if allowed != 1 {
		t.Fatalf("expected exactly one cross-manager probe, got %d", allowed)
	}

	if probe.CircuitProbeToken == "" {
		t.Fatal("shared half-open probe did not return its ownership token")
	}
	second.recordSuccess(ctx, &domain.Deployment{ID: deploymentID})
	if first.GetCircuitState(ctx, deploymentID) != CircuitHalfOpen {
		t.Fatal("request without the probe token cleared the shared half-open state")
	}
	probeManager.recordFailure(ctx, probe, 3, 1)
	if first.GetCircuitState(ctx, deploymentID) != CircuitOpen || second.GetCircuitState(ctx, deploymentID) != CircuitOpen {
		t.Fatal("failed probe did not restore the shared cooldown")
	}
	redisServer.FastForward(time.Second)
	probeAllowed, token := probeManager.allowDeploymentRequest(ctx, deploymentID)
	if !probeAllowed {
		t.Fatal("expected a recovery probe after the retried cooldown")
	}
	probe = &domain.Deployment{ID: deploymentID, CircuitProbeToken: token}
	other := managerOtherThan(first, second, probeManager)
	if otherAllowed, _ := other.allowDeploymentRequest(ctx, deploymentID); otherAllowed {
		t.Fatal("second manager acquired a probe while the shared lease was active")
	}

	probeManager.recordSuccess(ctx, probe)
	if first.GetCircuitState(ctx, deploymentID) != CircuitClosed || second.GetCircuitState(ctx, deploymentID) != CircuitClosed {
		t.Fatal("successful probe did not clear shared circuit state")
	}
	firstAllowed, _ := first.allowDeploymentRequest(ctx, deploymentID)
	secondAllowed, _ := second.allowDeploymentRequest(ctx, deploymentID)
	if !firstAllowed || !secondAllowed {
		t.Fatal("closed circuit should admit normal requests from both managers")
	}
}

func TestCircuitProbeLeaseExpiresAfterProbeProcessStops(t *testing.T) {
	ctx := context.Background()
	redisServer := miniredis.RunT(t)
	first := NewReliabilityManager(nil, nil, nil, nil, nil, nil, storage.NewRedisFabric(redisServer.Addr(), "", 0), config.RouterConfig{})
	second := NewReliabilityManager(nil, nil, nil, nil, nil, nil, storage.NewRedisFabric(redisServer.Addr(), "", 0), config.RouterConfig{})

	first.tripCooldown(ctx, "lease-expiry", 1)
	redisServer.FastForward(time.Second)
	if allowed, _ := first.allowDeploymentRequest(ctx, "lease-expiry"); !allowed {
		t.Fatal("first manager should acquire the probe lease")
	}
	if allowed, _ := second.allowDeploymentRequest(ctx, "lease-expiry"); allowed {
		t.Fatal("second manager acquired an active probe lease")
	}

	redisServer.FastForward(circuitProbeLeaseTTL + time.Second)
	if allowed, _ := second.allowDeploymentRequest(ctx, "lease-expiry"); !allowed {
		t.Fatal("expired probe lease did not allow another recovery probe")
	}
}

func managerOtherThan(first, second, selected *ReliabilityManager) *ReliabilityManager {
	if selected == first {
		return second
	}
	return first
}
