package cache

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
)

func TestResponseCache_SharedInvalidationAcrossReplicas(t *testing.T) {
	ctx := context.Background()
	server := miniredis.RunT(t)
	cacheA := NewResponseCache(true, time.Minute, storage.NewRedisFabric(server.Addr(), "", 0))
	cacheB := NewResponseCache(true, time.Minute, storage.NewRedisFabric(server.Addr(), "", 0))
	key := "same-request"

	cacheA.SetWithMeta(ctx, key, "org-1", &domain.CanonicalChatResponse{ID: "old", Model: "model-a"})
	got, ok := cacheB.Get(ctx, key) // Warm replica B's L1.
	if !ok || got.ID != "old" {
		t.Fatalf("initial shared cache lookup = (%v, %v), want old response", got, ok)
	}

	if _, _, err := cacheA.Invalidate(ctx, "org-1", ""); err != nil {
		t.Fatalf("invalidate organization: %v", err)
	}
	if got, ok := cacheB.Get(ctx, key); ok {
		t.Fatalf("replica B returned stale response after invalidation: %+v", got)
	}

	cacheA.SetWithMeta(ctx, key, "org-1", &domain.CanonicalChatResponse{ID: "new", Model: "model-a"})
	got, ok = cacheB.Get(ctx, key)
	if !ok || got.ID != "new" {
		t.Fatalf("lookup after repopulation = (%v, %v), want new response", got, ok)
	}
}

func TestResponseCache_L1IsMissWhenSharedEpochStateUnavailable(t *testing.T) {
	ctx := context.Background()
	server := miniredis.RunT(t)
	redisA := storage.NewRedisFabric(server.Addr(), "", 0)
	redisB := storage.NewRedisFabric(server.Addr(), "", 0)
	defer redisA.Client().Close()
	defer redisB.Client().Close()
	cacheA := NewResponseCache(true, time.Minute, redisA)
	cacheB := NewResponseCache(true, time.Minute, redisB)
	key := "same-request"

	cacheA.SetWithMeta(ctx, key, "org-1", &domain.CanonicalChatResponse{ID: "old", Model: "model-a"})
	if _, ok := cacheB.Get(ctx, key); !ok { // Warm B's L1 before the outage.
		t.Fatal("expected initial cache hit")
	}
	server.Close()
	if got, ok := cacheB.Get(ctx, key); ok {
		t.Fatalf("returned stale L1 response while shared epoch state was unavailable: %+v", got)
	}
}

func TestResponseCache_ModelInvalidationIsSharedAcrossOrganizations(t *testing.T) {
	ctx := context.Background()
	server := miniredis.RunT(t)
	cacheA := NewResponseCache(true, time.Minute, storage.NewRedisFabric(server.Addr(), "", 0))
	cacheB := NewResponseCache(true, time.Minute, storage.NewRedisFabric(server.Addr(), "", 0))
	key := "same-request"

	cacheA.SetWithMeta(ctx, key, "org-1", &domain.CanonicalChatResponse{ID: "old", Model: "model-a"})
	if _, ok := cacheB.Get(ctx, key); !ok {
		t.Fatal("expected initial cache hit")
	}
	if _, _, err := cacheA.Invalidate(ctx, "", "model-a"); err != nil {
		t.Fatalf("invalidate model: %v", err)
	}
	if got, ok := cacheB.Get(ctx, key); ok {
		t.Fatalf("model invalidation left stale response in another replica: %+v", got)
	}
}

func TestResponseCache_ReconnectedReplicaChecksMissedInvalidation(t *testing.T) {
	ctx := context.Background()
	server := miniredis.RunT(t)
	addr := server.Addr()
	redisA := storage.NewRedisFabric(addr, "", 0)
	redisB := storage.NewRedisFabric(addr, "", 0)
	defer redisA.Client().Close()
	defer redisB.Client().Close()
	cacheA := NewResponseCache(true, time.Minute, redisA)
	cacheB := NewResponseCache(true, time.Minute, redisB)
	key := "same-request"

	cacheA.SetWithMeta(ctx, key, "org-1", &domain.CanonicalChatResponse{ID: "old", Model: "model-a"})
	if _, ok := cacheB.Get(ctx, key); !ok { // Warm B's L1.
		t.Fatal("expected initial cache hit")
	}

	server.Close()
	if got, ok := cacheB.Get(ctx, key); ok {
		t.Fatalf("returned L1 response without verifying Redis during outage: %+v", got)
	}
	if err := server.Restart(); err != nil {
		t.Fatalf("restart Redis: %v", err)
	}

	// Simulate a replica reconnecting with its process-local L1 intact after it missed
	// any invalidation notification while disconnected.
	cacheB.redis = storage.NewRedisFabric(addr, "", 0)
	defer cacheB.redis.Client().Close()
	cacheAdmin := NewResponseCache(true, time.Minute, storage.NewRedisFabric(addr, "", 0))
	defer cacheAdmin.redis.Client().Close()
	if _, _, err := cacheAdmin.Invalidate(ctx, "org-1", ""); err != nil {
		t.Fatalf("invalidate while replica disconnected: %v", err)
	}
	if got, ok := cacheB.Get(ctx, key); ok {
		t.Fatalf("reconnected replica returned stale L1 response: %+v", got)
	}
}

func TestResponseCache_GlobalInvalidationIsSharedAcrossReplicas(t *testing.T) {
	ctx := context.Background()
	server := miniredis.RunT(t)
	redisA := storage.NewRedisFabric(server.Addr(), "", 0)
	redisB := storage.NewRedisFabric(server.Addr(), "", 0)
	defer redisA.Client().Close()
	defer redisB.Client().Close()
	cacheA := NewResponseCache(true, time.Minute, redisA)
	cacheB := NewResponseCache(true, time.Minute, redisB)
	key := "same-request"

	cacheA.SetWithMeta(ctx, key, "org-1", &domain.CanonicalChatResponse{ID: "old", Model: "model-a"})
	if _, ok := cacheB.Get(ctx, key); !ok {
		t.Fatal("expected initial cache hit")
	}
	if _, _, err := cacheA.Invalidate(ctx, "", ""); err != nil {
		t.Fatalf("global invalidation: %v", err)
	}
	if got, ok := cacheB.Get(ctx, key); ok {
		t.Fatalf("global invalidation left stale response on another replica: %+v", got)
	}
}

func TestResponseCache_CompletionsAndEmbeddingsL2RedisSharing(t *testing.T) {
	ctx := context.Background()
	server := miniredis.RunT(t)
	redisA := storage.NewRedisFabric(server.Addr(), "", 0)
	redisB := storage.NewRedisFabric(server.Addr(), "", 0)
	defer redisA.Client().Close()
	defer redisB.Client().Close()
	cacheA := NewResponseCache(true, time.Minute, redisA)
	cacheB := NewResponseCache(true, time.Minute, redisB)

	cmplKey := "cmpl-shared"
	cacheA.SetCompletionWithMeta(ctx, cmplKey, "org-1", &domain.CanonicalCompletionResponse{
		ID:      "cmpl-l2",
		Model:   "gpt-3.5-turbo-instruct",
		Choices: []domain.CanonicalCompletionChoice{{Index: 0, Text: "from-l2"}},
	})
	gotCmpl, ok := cacheB.GetCompletion(ctx, cmplKey)
	if !ok || gotCmpl.ID != "cmpl-l2" || gotCmpl.Choices[0].Text != "from-l2" {
		t.Fatalf("expected L2 Redis hit for completion on replica B, got (%+v, %v)", gotCmpl, ok)
	}

	embKey := "emb-shared"
	cacheA.SetEmbeddingWithMeta(ctx, embKey, "org-1", &domain.CanonicalEmbeddingResponse{
		Model: "text-embedding-3-small",
		Data:  []domain.EmbeddingData{{Index: 0, Embedding: []float64{0.1, 0.2}}},
	})
	gotEmb, ok := cacheB.GetEmbedding(ctx, embKey)
	if !ok || len(gotEmb.Data) != 1 || gotEmb.Data[0].Embedding[1] != 0.2 {
		t.Fatalf("expected L2 Redis hit for embedding on replica B, got (%+v, %v)", gotEmb, ok)
	}

	if _, _, err := cacheA.Invalidate(ctx, "org-1", ""); err != nil {
		t.Fatalf("invalidate org-1: %v", err)
	}
	if _, ok := cacheB.GetCompletion(ctx, cmplKey); ok {
		t.Fatal("expected completion cache invalidated across replicas")
	}
	if _, ok := cacheB.GetEmbedding(ctx, embKey); ok {
		t.Fatal("expected embedding cache invalidated across replicas")
	}
}
