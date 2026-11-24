package cache

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseCacheControl_CaseInsensitiveAndDisablePrecedence(t *testing.T) {
	opts := ParseCacheControl("no-cache", "force", "0.95")
	assert.True(t, opts.Bypass)
	assert.False(t, opts.Force)

	opts = ParseCacheControl("max-age=0", "enabled", "")
	assert.True(t, opts.Bypass)

	opts = ParseCacheControl("", "FORCE", "0.88")
	assert.False(t, opts.Bypass)
	assert.True(t, opts.Force)
	assert.True(t, opts.Enabled)
	assert.InDelta(t, 0.88, opts.SimilarityOverride, 1e-9)

	// Out-of-range similarity override is ignored.
	opts = ParseCacheControl("", "enabled", "1.5")
	assert.Equal(t, 0.0, opts.SimilarityOverride)
}

func TestResponseCache_ComputeKeyCollisionResistanceAndVirtualAliasScope(t *testing.T) {
	rc := NewLocalResponseCache(true, time.Hour, 64)

	reqA := &domain.CanonicalChatRequest{
		Model:    "gpt-4o-mini",
		Messages: []domain.CanonicalMessage{{Role: "user", Content: "hi"}},
	}
	reqB := &domain.CanonicalChatRequest{
		Model:    "gpt-4o-mini",
		Messages: []domain.CanonicalMessage{{Role: "user", Content: "hi!"}},
	}
	assert.NotEqual(t, rc.ComputeKey("org-1", reqA), rc.ComputeKey("org-1", reqB))
	assert.NotEqual(t, rc.ComputeKey("org-1", reqA), rc.ComputeKey("org-2", reqA))

	// RequestID does not perturb key.
	reqIDCopy := *reqA
	reqIDCopy.RequestID = "req-999"
	assert.Equal(t, rc.ComputeKey("org-1", reqA), rc.ComputeKey("org-1", &reqIDCopy))

	// Both "auto" and "router/*" aliases scope by TeamID and AllowedModelScope.
	for _, alias := range []string{"auto", "router/semantic", "router/quality", "router/adaptive", "router/heuristic"} {
		r := &domain.CanonicalChatRequest{
			Model:    alias,
			Messages: []domain.CanonicalMessage{{Role: "user", Content: "hello"}},
		}
		k1 := rc.ComputeKeyWithScope("org-1", "team-a", "key:fast", r)
		k2 := rc.ComputeKeyWithScope("org-1", "team-b", "key:fast", r)
		k3 := rc.ComputeKeyWithScope("org-1", "team-a", "key:reasoning", r)
		assert.NotEqual(t, k1, k2, "alias %s must scope by teamID", alias)
		assert.NotEqual(t, k1, k3, "alias %s must scope by allowedModelScope", alias)
	}

	// Unencodable ExtraParams disables caching instead of collapsing to empty digest.
	bad := &domain.CanonicalChatRequest{
		Model:       "gpt-4o-mini",
		Messages:    []domain.CanonicalMessage{{Role: "user", Content: "hi"}},
		ExtraParams: map[string]any{"bad": func() {}},
	}
	assert.Equal(t, "", rc.ComputeKey("org-1", bad))
}

func TestResponseCache_ExcludedCallTypesDefaultExcludesEmbeddings(t *testing.T) {
	cfg := config.Default().Cache
	rc := NewResponseCacheFromConfig(cfg, nil, nil)

	embReq := &domain.CanonicalEmbeddingRequest{Model: "text-embedding-3-small", Input: []string{"hello"}}
	assert.False(t, rc.IsEmbeddingCacheable(embReq, RequestCacheOptions{}), "embeddings must be excluded by default")

	cfg.ExcludedCallTypes = []string{}
	rcOptIn := NewResponseCacheFromConfig(cfg, nil, nil)
	assert.True(t, rcOptIn.IsEmbeddingCacheable(embReq, RequestCacheOptions{}))
	assert.False(t, rcOptIn.IsEmbeddingCacheable(embReq, RequestCacheOptions{Bypass: true}))
}

func TestResponseCache_DeepCopyRaceSafety(t *testing.T) {
	rc := NewLocalResponseCache(true, time.Hour, 64)
	ctx := context.Background()
	zero := 0.0
	req := &domain.CanonicalChatRequest{
		Model:       "gpt-4o-mini",
		Temperature: &zero,
		Messages:    []domain.CanonicalMessage{{Role: "user", Content: "hello"}},
	}
	miss := rc.LookupChat(ctx, "org-1", "", "", req, RequestCacheOptions{})
	rc.StoreChat(ctx, miss, "org-1", &domain.CanonicalChatResponse{
		ID:       "chatcmpl-race",
		Provider: domain.ProviderOpenAI,
		Model:    "gpt-4o-mini",
		Metadata: map[string]string{"k": "v"},
		Choices: []domain.CanonicalChoice{{
			Index: 0,
			Message: domain.CanonicalMessage{
				Role:    "assistant",
				Content: "secret@example.com",
			},
		}},
	})

	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 50 {
				hit := rc.LookupChat(ctx, "org-1", "", "", req, RequestCacheOptions{})
				require.True(t, hit.Hit)
				hit.Response.Metadata["k"] = "mutated"
				hit.Response.Choices[0].Message.Content = "[REDACTED]"
			}
		}()
	}
	wg.Wait()

	finalHit := rc.LookupChat(ctx, "org-1", "", "", req, RequestCacheOptions{})
	require.True(t, finalHit.Hit)
	assert.Equal(t, "v", finalHit.Response.Metadata["k"])
	assert.Equal(t, "secret@example.com", finalHit.Response.Choices[0].Message.Content)
}

func TestResponseCache_SeedMakesHighTemperatureCacheable(t *testing.T) {
	rc := NewLocalResponseCache(true, time.Hour, 64)
	temp := 0.7

	// Without seed, temperature > 0 is not cacheable unless forced.
	reqNoSeed := &domain.CanonicalChatRequest{
		Model:       "gpt-4o-mini",
		Temperature: &temp,
		Messages:    []domain.CanonicalMessage{{Role: "user", Content: "roll dice"}},
	}
	assert.False(t, rc.IsCacheable(reqNoSeed, RequestCacheOptions{}))

	// With non-nil ExtraParams["seed"], temperature > 0 IS cacheable (H3).
	reqWithSeed := &domain.CanonicalChatRequest{
		Model:       "gpt-4o-mini",
		Temperature: &temp,
		Messages:    []domain.CanonicalMessage{{Role: "user", Content: "roll dice"}},
		ExtraParams: map[string]any{"seed": 42},
	}
	assert.True(t, rc.IsCacheable(reqWithSeed, RequestCacheOptions{}))

	// Nil seed does not bypass temperature check.
	reqNilSeed := &domain.CanonicalChatRequest{
		Model:       "gpt-4o-mini",
		Temperature: &temp,
		Messages:    []domain.CanonicalMessage{{Role: "user", Content: "roll dice"}},
		ExtraParams: map[string]any{"seed": nil},
	}
	assert.False(t, rc.IsCacheable(reqNilSeed, RequestCacheOptions{}))
}
