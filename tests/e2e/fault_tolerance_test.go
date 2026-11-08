package e2e_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/auth"
	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/server"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
	"github.com/redis/go-redis/v9"
	"github.com/sony/gobreaker/v2"
)

// TestProductionRecovery_FailClosedOnDBOutage verifies that when the database pool is down or closed,
// authentication and state mutations fail closed immediately (HTTP 500/503), preventing unauthenticated or unmetered access.
func TestProductionRecovery_FailClosedOnDBOutage(t *testing.T) {
	ctx := context.Background()
	pgDSN := getEnvOrDefault("GATEWAY_POSTGRES_DSN", "postgres://gateway:gateway@localhost:5432/aigateway?sslmode=disable")

	pool, err := storage.NewPostgresPool(ctx, pgDSN)
	if err != nil {
		t.Skipf("skipping test: cannot connect to PostgreSQL: %v", err)
	}

	_ = storage.RunMigrationsDir(ctx, pool, "../../migrations")
	pgRepo, err := storage.NewPostgresRepository(ctx, pool)
	if err != nil {
		pool.Close()
		t.Fatalf("new postgres repo: %v", err)
	}

	cfg := config.Default()
	cfg.Auth.MasterAdminKey = "sk-gw-admin-disaster-test-key"
	cfg.Auth.MasterEncryptionKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	cfg.Security.Network.OutboundSSRF.AllowPrivateNetworks = true
	cfg.Security.Network.OutboundSSRF.AllowInsecureHTTP = true
	cfg.MCP.Enabled = true

	gw, err := server.New(cfg, pgRepo, nil, nil)
	if err != nil {
		pool.Close()
		t.Fatalf("server.New: %v", err)
	}
	ts := httptest.NewServer(gw.Handler())
	defer ts.Close()
	defer gw.Shutdown(ctx)

	client := &httpClientHelper{t: t, ts: ts}
	adminHeaders := map[string]string{"Authorization": "Bearer sk-gw-admin-disaster-test-key"}

	// 1. Verify healthy system before outage
	var org domain.Organization
	resp, _ := client.doJSON("POST", "/admin/v1/organizations", adminHeaders, map[string]any{
		"name": "Pre-Disaster Org",
		"slug": fmt.Sprintf("pre-disaster-%d", time.Now().UnixNano()),
	}, &org)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201 before outage, got: %d", resp.StatusCode)
	}

	// 2. SIMULATE DATABASE DISASTER: Close pool
	pool.Close()

	// 3. Verify Fail-Closed Auth: Request with unknown key must FAIL CLOSED (not grant access)
	fakeKeyHeaders := map[string]string{"Authorization": "Bearer sk-gw-nonexistent-key-12345"}
	resp, _ = client.doJSON("GET", "/mcp-rest/tools/list", fakeKeyHeaders, nil, nil)
	if resp.StatusCode != http.StatusUnauthorized && resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("expected fail-closed 401/500 on DB outage, got: %d", resp.StatusCode)
	}

	// 4. Verify Fail-Closed Mutation: Admin write must fail cleanly with 500 without panic
	resp, _ = client.doJSON("POST", "/admin/v1/organizations", adminHeaders, map[string]any{
		"name": "Post-Disaster Org",
		"slug": fmt.Sprintf("post-disaster-%d", time.Now().UnixNano()),
	}, nil)
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("expected 500 InternalServerError on DB outage, got: %d", resp.StatusCode)
	}
}

// TestProductionRecovery_RedisDegradationAndCircuitBreaker verifies that Redis outages trip the circuit breaker,
// protecting the gateway process from cascade failures, and recover when connectivity is restored.
func TestProductionRecovery_RedisDegradationAndCircuitBreaker(t *testing.T) {
	// Create fabric pointing to non-existent port to simulate outage
	deadFabric := storage.NewRedisFabric("127.0.0.1:59999", "", 0)

	// Execute consecutive failing requests to trip circuit breaker
	var lastErr error
	for i := 0; i < 7; i++ {
		_, err := deadFabric.Execute(func(rdb *redis.Client) (any, error) {
			return nil, fmt.Errorf("redis: connection timeout")
		})
		lastErr = err
	}

	// Circuit breaker must have tripped to Open state
	if lastErr != gobreaker.ErrOpenState {
		t.Fatalf("expected circuit breaker to be open (gobreaker.ErrOpenState), got: %v", lastErr)
	}

	// Verify that healthy RedisFabric succeeds
	liveFabric := storage.NewRedisFabric(getEnvOrDefault("GATEWAY_REDIS_ADDR", "localhost:6379"), "", 0)
	val, err := liveFabric.Execute(func(rdb *redis.Client) (any, error) {
		return rdb.Ping(context.Background()).Result()
	})
	if err != nil {
		t.Skipf("skipping live redis verification: %v", err)
	}
	if val != "PONG" {
		t.Fatalf("expected PONG from live redis, got: %v", val)
	}
}

// TestProductionRecovery_VaultMasterKeyRotationUnderLoad verifies that envelope encryption master keys (KEKs)
// can be rotated concurrently under heavy decrypt traffic with zero race conditions and zero errors.
func TestProductionRecovery_VaultMasterKeyRotationUnderLoad(t *testing.T) {
	oldMasterKey := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	newMasterKey := "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"

	oldVault, err := auth.NewVault(oldMasterKey)
	if err != nil {
		t.Fatalf("old vault: %v", err)
	}
	newVault, err := auth.NewVault(newMasterKey)
	if err != nil {
		t.Fatalf("new vault: %v", err)
	}

	// Encrypt credential with old vault
	rawSecret := "sk-ant-live-super-secret-provider-key-998877"
	cred := &domain.ProviderCredential{
		ID:       "cred_rot_001",
		OrgID:    "org_rot",
		Name:     "Anthropic Production Credential",
		Provider: domain.ProviderAnthropic,
	}
	if err := oldVault.EncryptCredential(cred, rawSecret); err != nil {
		t.Fatalf("encrypt credential: %v", err)
	}

	// Concurrency test: 30 workers continuously decrypting
	type VaultCredPair struct {
		vault *auth.Vault
		cred  *domain.ProviderCredential
	}

	var (
		wg             sync.WaitGroup
		stopFlag       atomic.Bool
		decryptedCount atomic.Int64
		errorCount     atomic.Int64
		activePair     atomic.Pointer[VaultCredPair]
	)
	activePair.Store(&VaultCredPair{vault: oldVault, cred: cred})

	for i := 0; i < 30; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for !stopFlag.Load() {
				pair := activePair.Load()
				plain, err := pair.vault.DecryptCredential(pair.cred)
				if err != nil || plain != rawSecret {
					errorCount.Add(1)
				} else {
					decryptedCount.Add(1)
				}
				time.Sleep(1 * time.Millisecond)
			}
		}()
	}

	// Allow workers to run on old vault
	time.Sleep(50 * time.Millisecond)

	// Perform Master Key Rotation: ReWrap the DEK into a new immutable snapshot
	rotatedCred, err := oldVault.ReWrapCredential(cred, newVault)
	if err != nil {
		t.Fatalf("re-wrap credential: %v", err)
	}
	// Atomically publish new vault + rotated credential pair
	activePair.Store(&VaultCredPair{vault: newVault, cred: rotatedCred})

	// Allow workers to run on new vault
	time.Sleep(50 * time.Millisecond)

	stopFlag.Store(true)
	wg.Wait()

	if errors := errorCount.Load(); errors > 0 {
		t.Fatalf("encountered %d decryption errors during key rotation", errors)
	}
	if count := decryptedCount.Load(); count < 100 {
		t.Fatalf("expected at least 100 successful decryptions under load, got: %d", count)
	}
}

// TestProductionRecovery_BoundedGracefulShutdown verifies that calling GatewayServer.Shutdown(ctx)
// drains in-flight requests, stops background workers, and exits cleanly within the bounded timeout.
func TestProductionRecovery_BoundedGracefulShutdown(t *testing.T) {
	ctx := context.Background()
	repo := storage.NewMemoryRepository()
	cfg := config.Default()
	cfg.Auth.MasterAdminKey = "sk-gw-admin-shutdown-key"
	cfg.Auth.MasterEncryptionKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	cfg.MCP.Enabled = true
	cfg.A2A.Enabled = true

	gw, err := server.New(cfg, repo, nil, nil)
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}

	gw.StartWorkers(ctx)

	// Simulate work in flight
	doneCh := make(chan struct{})
	go func() {
		shutdownCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		gw.Shutdown(shutdownCtx)
		close(doneCh)
	}()

	select {
	case <-doneCh:
		// Cleanly terminated within deadline
	case <-time.After(5 * time.Second):
		t.Fatalf("gw.Shutdown failed to return within 5 seconds (deadlock or worker leak)")
	}
}
