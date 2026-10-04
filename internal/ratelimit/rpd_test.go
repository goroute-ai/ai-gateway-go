package ratelimit

import (
	"context"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAcquireDescriptors_RPDLimitRedisAndLocal(t *testing.T) {
	ctx := context.Background()

	runMode := func(t *testing.T, withRedis bool) {
		t.Helper()
		var rf *storage.RedisFabric
		if withRedis {
			mr := miniredis.RunT(t)
			rf = storage.NewRedisFabric(mr.Addr(), "", 0)
			t.Cleanup(func() { _ = rf.Client().Close() })
		}

		lim := NewLimiter(rf, 60, 300)
		if !withRedis {
			lim.SetFallbackToLocalOnOutage(true)
		}

		day1 := time.Date(2026, 11, 19, 23, 59, 0, 0, time.UTC)
		var nowNs atomic.Int64
		nowNs.Store(day1.UnixNano())
		lim.SetNowFunc(func() time.Time { return time.Unix(0, nowNs.Load()).UTC() })

		descs := []domain.RateLimitDescriptor{
			{
				ScopeType: domain.QuotaScopeKey,
				ScopeID:   "vk-rpd-1",
				RPDLimit:  3,
			},
			{
				ScopeType: domain.QuotaScopeTeam,
				ScopeID:   "team-rpd-1",
				RPDLimit:  10,
			},
		}

		// First 3 requests succeed even if separated across minutes within the same UTC day.
		for i := 0; i < 3; i++ {
			rel, _, err := lim.AcquireDescriptorsWithMeta(ctx, "org-rpd", "req-day1-"+string(rune('a'+i)), 10, 5, 0, descs)
			require.NoError(t, err, "request %d on day 1 should succeed", i+1)
			rel(10, 5, 0)
		}

		// 4th request exceeds vk-rpd-1 RPDLimit=3 with 429 + _RPD_EXCEEDED + rpd metadata.
		_, _, err := lim.AcquireDescriptorsWithMeta(ctx, "org-rpd", "req-day1-4", 10, 5, 0, descs)
		require.Error(t, err)
		var gwErr *domain.GatewayError
		require.ErrorAs(t, err, &gwErr)
		assert.Equal(t, http.StatusTooManyRequests, gwErr.StatusCode)
		assert.Equal(t, "key_rpd_exceeded", gwErr.Code)
		require.NotNil(t, gwErr.RateLimitMeta)
		assert.Equal(t, "key", gwErr.RateLimitMeta.Scope)
		assert.Equal(t, "rpd", gwErr.RateLimitMeta.LimitType)
		assert.Equal(t, 3, gwErr.RateLimitMeta.LimitRequests)
		assert.Equal(t, 0, gwErr.RateLimitMeta.RemainingRequests)

		// All-or-nothing check: team-rpd-1 should remain at 3 (not bumped by denied 4th request),
		// so another key on the same team can still consume remaining team RPD=10.
		otherKey := []domain.RateLimitDescriptor{
			{ScopeType: domain.QuotaScopeKey, ScopeID: "vk-rpd-2", RPDLimit: 2},
			{ScopeType: domain.QuotaScopeTeam, ScopeID: "team-rpd-1", RPDLimit: 4},
		}
		relOther, _, err := lim.AcquireDescriptorsWithMeta(ctx, "org-rpd", "req-other-1", 10, 5, 0, otherKey)
		require.NoError(t, err, "team counter must stay at 3 after atomic deny of vk-rpd-1")
		relOther(10, 5, 0)

		// Advancing clock past UTC midnight rolls over to a fresh day bucket.
		day2 := time.Date(2026, 11, 20, 0, 1, 0, 0, time.UTC)
		nowNs.Store(day2.UnixNano())
		relDay2, _, err := lim.AcquireDescriptorsWithMeta(ctx, "org-rpd", "req-day2-1", 10, 5, 0, descs[:1])
		require.NoError(t, err, "UTC midnight rollover must reset RPD bucket")
		relDay2(10, 5, 0)
	}

	t.Run("redis", func(t *testing.T) {
		runMode(t, true)
	})
	t.Run("local_fallback", func(t *testing.T) {
		runMode(t, false)
	})
}
