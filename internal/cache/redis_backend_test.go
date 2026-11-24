package cache

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRedisBackend_ExactMatchSharingAndInvalidation(t *testing.T) {
	mr := miniredis.RunT(t)
	fabricA := storage.NewRedisFabric(mr.Addr(), "", 0)
	fabricB := storage.NewRedisFabric(mr.Addr(), "", 0)
	t.Cleanup(func() {
		_ = fabricA.Client().Close()
		_ = fabricB.Client().Close()
	})

	cfg := config.Default().Cache
	cfg.Type = config.CacheTypeRedis
	cfg.ExcludedCallTypes = []string{} // Enable embeddings too for this test.

	cacheA := NewResponseCacheFromConfig(cfg, fabricA, nil)
	cacheB := NewResponseCacheFromConfig(cfg, fabricB, nil)
	require.Equal(t, config.CacheTypeRedis, cacheA.Type())

	ctx := context.Background()
	zero := 0.0
	req := &domain.CanonicalChatRequest{
		Model:       "gpt-4o-mini",
		Temperature: &zero,
		Messages:    []domain.CanonicalMessage{{Role: "user", Content: "ping"}},
	}
	resp := &domain.CanonicalChatResponse{
		ID:       "chatcmpl-1",
		Provider: domain.ProviderOpenAI,
		Model:    "gpt-4o-mini",
		Choices:  []domain.CanonicalChoice{{Index: 0, Message: domain.CanonicalMessage{Role: "assistant", Content: "pong"}}},
	}

	// Miss on replica A, then store.
	missA := cacheA.LookupChat(ctx, "org-1", "team-1", "", req, RequestCacheOptions{})
	require.True(t, missA.Eligible)
	require.False(t, missA.Hit)
	cacheA.StoreChat(ctx, missA, "org-1", resp)

	// Hit on replica B (shared Redis KV).
	hitB := cacheB.LookupChat(ctx, "org-1", "team-1", "", req, RequestCacheOptions{})
	require.True(t, hitB.Hit)
	assert.Equal(t, CacheHitTypeExact, hitB.CacheType)
	assert.Equal(t, "pong", hitB.Response.Choices[0].Message.Content)

	// Strict tenant isolation: org-2 must miss.
	missOrg2 := cacheB.LookupChat(ctx, "org-2", "team-1", "", req, RequestCacheOptions{})
	assert.False(t, missOrg2.Hit)

	// Store second model in org-1 and org-2 to test scoped invalidation.
	reqOther := &domain.CanonicalChatRequest{
		Model:       "claude-sonnet",
		Temperature: &zero,
		Messages:    []domain.CanonicalMessage{{Role: "user", Content: "ping"}},
	}
	missOther := cacheA.LookupChat(ctx, "org-1", "team-1", "", reqOther, RequestCacheOptions{})
	cacheA.StoreChat(ctx, missOther, "org-1", &domain.CanonicalChatResponse{
		ID:       "chatcmpl-2",
		Provider: domain.ProviderAnthropic,
		Model:    "claude-sonnet",
		Choices:  []domain.CanonicalChoice{{Index: 0, Message: domain.CanonicalMessage{Role: "assistant", Content: "pong-claude"}}},
	})
	cacheA.StoreChat(ctx, missOrg2, "org-2", resp)

	// Model-scoped invalidation within org-1 removes only (org-1, gpt-4o-mini).
	purged, rev, err := cacheB.Invalidate(ctx, "org-1", "gpt-4o-mini")
	require.NoError(t, err)
	assert.Equal(t, 1, purged)
	assert.Equal(t, int64(1), rev)

	assert.False(t, cacheA.LookupChat(ctx, "org-1", "team-1", "", req, RequestCacheOptions{}).Hit)
	assert.True(t, cacheA.LookupChat(ctx, "org-1", "team-1", "", reqOther, RequestCacheOptions{}).Hit)
	assert.True(t, cacheA.LookupChat(ctx, "org-2", "team-1", "", req, RequestCacheOptions{}).Hit)

	// Global invalidation purges all remaining entries.
	purged, rev, err = cacheA.Invalidate(ctx, "", "")
	require.NoError(t, err)
	assert.Equal(t, 2, purged)
	assert.Equal(t, int64(1), rev)
	assert.False(t, cacheB.LookupChat(ctx, "org-1", "team-1", "", reqOther, RequestCacheOptions{}).Hit)
	assert.False(t, cacheB.LookupChat(ctx, "org-2", "team-1", "", req, RequestCacheOptions{}).Hit)
}

func TestRedisBackend_CompletionsEmbeddingsAndTTLExpiry(t *testing.T) {
	mr := miniredis.RunT(t)
	fabric := storage.NewRedisFabric(mr.Addr(), "", 0)
	t.Cleanup(func() { _ = fabric.Client().Close() })

	cfg := config.Default().Cache
	cfg.Type = config.CacheTypeRedis
	cfg.DefaultTTL = 30 * time.Second
	cfg.ExcludedCallTypes = []string{} // Opt in to embeddings caching.

	rc := NewResponseCacheFromConfig(cfg, fabric, nil)
	ctx := context.Background()

	zero := 0.0
	cmplReq := &domain.CanonicalCompletionRequest{Model: "gpt-3.5-turbo-instruct", Prompt: domain.CompletionPrompt{Strings: []string{"hello"}}, Temperature: &zero}
	require.True(t, rc.IsCompletionCacheable(cmplReq, RequestCacheOptions{}))
	cmplKey := rc.ComputeCompletionKeyWithScope("org-1", "t1", "", cmplReq)
	rc.SetCompletionWithMeta(ctx, cmplKey, "org-1", &domain.CanonicalCompletionResponse{
		ID:      "cmpl-1",
		Model:   "gpt-3.5-turbo-instruct",
		Choices: []domain.CanonicalCompletionChoice{{Index: 0, Text: "world"}},
	}, "legacy-alias")
	gotCmpl, hit := rc.GetCompletion(ctx, "org-1", cmplKey)
	require.True(t, hit)
	assert.Equal(t, "world", gotCmpl.Choices[0].Text)

	embReq := &domain.CanonicalEmbeddingRequest{Model: "text-embedding-3-small", Input: []string{"hello"}}
	require.True(t, rc.IsEmbeddingCacheable(embReq, RequestCacheOptions{}))
	embKey := rc.ComputeEmbeddingKeyWithScope("org-1", "t1", "", embReq)
	rc.SetEmbeddingWithMeta(ctx, embKey, "org-1", &domain.CanonicalEmbeddingResponse{
		Model: "text-embedding-3-small",
		Data:  []domain.EmbeddingData{{Index: 0, Embedding: []float64{0.1, 0.2}}},
	}, "embed-alias")
	gotEmb, hit := rc.GetEmbedding(ctx, "org-1", embKey)
	require.True(t, hit)
	assert.Equal(t, []float64{0.1, 0.2}, gotEmb.Data[0].Embedding)

	// ModelGroup alias invalidation purges completion & embedding entries via requestedModel (M2 + M3).
	purged, _, err := rc.Invalidate(ctx, "org-1", "legacy-alias")
	require.NoError(t, err)
	assert.Equal(t, 1, purged)
	_, hit = rc.GetCompletion(ctx, "org-1", cmplKey)
	assert.False(t, hit)
	_, hit = rc.GetEmbedding(ctx, "org-1", embKey)
	assert.True(t, hit, "invalidating legacy-alias must not touch embed-alias")

	// Fast-forward TTL in miniredis -> expired.
	mr.FastForward(31 * time.Second)
	_, hit = rc.GetEmbedding(ctx, "org-1", embKey)
	assert.False(t, hit)
}

func TestRedisBackend_FailOpenOnOutage(t *testing.T) {
	mr := miniredis.RunT(t)
	fabric := storage.NewRedisFabric(mr.Addr(), "", 0)
	t.Cleanup(func() { _ = fabric.Client().Close() })

	cfg := config.Default().Cache
	cfg.Type = config.CacheTypeRedis
	rc := NewResponseCacheFromConfig(cfg, fabric, nil)

	mr.Close() // Simulate Redis outage.

	zero := 0.0
	req := &domain.CanonicalChatRequest{
		Model:       "gpt-4o-mini",
		Temperature: &zero,
		Messages:    []domain.CanonicalMessage{{Role: "user", Content: "ping"}},
	}
	res := rc.LookupChat(context.Background(), "org-1", "", "", req, RequestCacheOptions{})
	assert.True(t, res.Eligible)
	assert.False(t, res.Hit)
	assert.GreaterOrEqual(t, rc.Metrics().Errors, uint64(1))
}
