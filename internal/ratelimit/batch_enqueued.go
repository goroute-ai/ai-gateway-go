package ratelimit

import (
	"context"
	_ "embed"
	"fmt"
	"strings"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/redis/go-redis/v9"
)

const defaultBatchEnqueuedHoldTTLSec = 90000 // 25 hours (exceeds 24h completion_window)

//go:embed scripts/batch_enqueued_acquire.lua
var batchEnqueuedAcquireLua string

//go:embed scripts/batch_enqueued_release.lua
var batchEnqueuedReleaseLua string

type localBatchHold struct {
	keyID  string
	teamID string
	userID string
	orgID  string
	tokens int64
}

func hasBatchEnqueuedLimits(idCtx *domain.IdentityContext) bool {
	return idCtx != nil && (idCtx.KeyBatchEnqueuedTokenLimit > 0 ||
		idCtx.TeamBatchEnqueuedTokenLimit > 0 ||
		idCtx.UserBatchEnqueuedTokenLimit > 0 ||
		idCtx.OrgBatchEnqueuedTokenLimit > 0)
}

func batchEnqueuedScopeTuple(tag, scope, entityID string) (string, string, string) {
	if entityID == "" {
		return "", "", ""
	}
	base := fmt.Sprintf("gw:batch:%s:enqueued:%s:%s", tag, scope, entityID)
	return base, base + ":sum", base + ":amounts"
}

func batchEnqueuedMetaKey(orgID, batchID string) string {
	return fmt.Sprintf("gw:batch:%s:enqueued:meta:%s", orgHashTag(orgID), batchID)
}

func batchEnqueuedKeys(orgID, keyID, teamID, userID, batchID string) []string {
	tag := orgHashTag(orgID)
	effectiveOrgID := orgID
	if effectiveOrgID == "" {
		effectiveOrgID = "default"
	}
	keyZ, keyS, keyA := batchEnqueuedScopeTuple(tag, "key", keyID)
	teamZ, teamS, teamA := batchEnqueuedScopeTuple(tag, "team", teamID)
	userZ, userS, userA := batchEnqueuedScopeTuple(tag, "user", userID)
	orgZ, orgS, orgA := batchEnqueuedScopeTuple(tag, "org", effectiveOrgID)
	return []string{
		keyZ, keyS, keyA,
		teamZ, teamS, teamA,
		userZ, userS, userA,
		orgZ, orgS, orgA,
		batchEnqueuedMetaKey(orgID, batchID),
	}
}

func encodeBatchHoldMeta(keyID, teamID, userID string) string {
	return keyID + "\n" + teamID + "\n" + userID
}

func decodeBatchHoldMeta(raw string) (keyID, teamID, userID string, ok bool) {
	parts := strings.Split(raw, "\n")
	if len(parts) != 3 {
		return "", "", "", false
	}
	return parts[0], parts[1], parts[2], true
}

// AcquireBatchEnqueuedTokens atomically enforces batch_enqueued_token_limit across
// Key, Team, User, and Org scopes and records an enqueued token hold for batchID.
func (l *Limiter) AcquireBatchEnqueuedTokens(ctx context.Context, idCtx *domain.IdentityContext, batchID string, estimatedTokens int64) error {
	if l == nil || idCtx == nil {
		return nil
	}
	enabled, fallbackLocal, _, _, _, _ := l.configSnapshot()
	if !enabled || !hasBatchEnqueuedLimits(idCtx) {
		return nil
	}
	if batchID == "" {
		return fmt.Errorf("batch ID is required for enqueued token hold")
	}
	if estimatedTokens < 0 {
		estimatedTokens = 0
	}

	if l.redis != nil && l.redis.Client() != nil {
		keys := batchEnqueuedKeys(idCtx.OrgID, idCtx.VirtualKeyID, idCtx.TeamID, idCtx.UserID, batchID)
		argv := []any{
			idCtx.KeyBatchEnqueuedTokenLimit,
			idCtx.TeamBatchEnqueuedTokenLimit,
			idCtx.UserBatchEnqueuedTokenLimit,
			idCtx.OrgBatchEnqueuedTokenLimit,
			estimatedTokens,
			batchID,
			defaultBatchEnqueuedHoldTTLSec,
			encodeBatchHoldMeta(idCtx.VirtualKeyID, idCtx.TeamID, idCtx.UserID),
		}
		res, err := l.redis.Execute(func(rdb redis.UniversalClient) (any, error) {
			rCtx, cancel := l.withRedisTimeout(ctx)
			defer cancel()
			return l.batchAcquireScr.Run(rCtx, rdb, keys, argv...).Slice()
		})
		if err == nil {
			if slice, ok := res.([]any); ok && len(slice) >= 2 {
				allowed, _ := slice[0].(int64)
				reason, _ := slice[1].(string)
				if allowed == 0 {
					return toQuotaError(reason)
				}
				return nil
			}
		}
		if !fallbackLocal {
			return limiterUnavailableError()
		}
	}

	if !fallbackLocal {
		return limiterUnavailableError()
	}
	return l.acquireBatchEnqueuedLocal(idCtx, batchID, estimatedTokens)
}

// ReleaseBatchEnqueuedTokens idempotently releases the enqueued token hold for batchID
// across Key, Team, User, and Org scopes when a batch reaches a terminal state.
func (l *Limiter) ReleaseBatchEnqueuedTokens(ctx context.Context, idCtx *domain.IdentityContext, batchID string) error {
	if l == nil || idCtx == nil || batchID == "" {
		return nil
	}
	enabled, _, _, _, _, _ := l.configSnapshot()
	if !enabled {
		return nil
	}

	l.releaseBatchEnqueuedLocal(batchID)

	if l.redis == nil || l.redis.Client() == nil {
		return nil
	}

	keyID, teamID, userID := idCtx.VirtualKeyID, idCtx.TeamID, idCtx.UserID
	metaKey := batchEnqueuedMetaKey(idCtx.OrgID, batchID)
	if rawRes, err := l.redis.Execute(func(rdb redis.UniversalClient) (any, error) {
		rCtx, cancel := l.withRedisTimeout(ctx)
		defer cancel()
		return rdb.Get(rCtx, metaKey).Result()
	}); err == nil {
		if rawStr, ok := rawRes.(string); ok {
			if mk, mt, mu, parsed := decodeBatchHoldMeta(rawStr); parsed {
				keyID, teamID, userID = mk, mt, mu
			}
		}
	}

	keys := batchEnqueuedKeys(idCtx.OrgID, keyID, teamID, userID, batchID)
	_, err := l.redis.Execute(func(rdb redis.UniversalClient) (any, error) {
		rCtx, cancel := l.withRedisTimeout(ctx)
		defer cancel()
		return l.batchReleaseScr.Run(rCtx, rdb, keys, batchID).Result()
	})
	return err
}

func (l *Limiter) acquireBatchEnqueuedLocal(idCtx *domain.IdentityContext, batchID string, estimatedTokens int64) error {
	l.localMu.Lock()
	defer l.localMu.Unlock()

	if _, exists := l.localBatchHolds[batchID]; exists {
		return toQuotaError("BATCH_ENQUEUED_CONFLICT")
	}

	effectiveOrgID := idCtx.OrgID
	if effectiveOrgID == "" {
		effectiveOrgID = "default"
	}

	type batchScope struct {
		key     string
		id      string
		limit   int64
		errCode string
	}
	scopes := []batchScope{
		{key: "key:" + idCtx.VirtualKeyID, id: idCtx.VirtualKeyID, limit: idCtx.KeyBatchEnqueuedTokenLimit, errCode: "KEY_BATCH_ENQUEUED_TOKENS_EXCEEDED"},
		{key: "team:" + idCtx.TeamID, id: idCtx.TeamID, limit: idCtx.TeamBatchEnqueuedTokenLimit, errCode: "TEAM_BATCH_ENQUEUED_TOKENS_EXCEEDED"},
		{key: "user:" + idCtx.UserID, id: idCtx.UserID, limit: idCtx.UserBatchEnqueuedTokenLimit, errCode: "USER_BATCH_ENQUEUED_TOKENS_EXCEEDED"},
		{key: "org:" + effectiveOrgID, id: effectiveOrgID, limit: idCtx.OrgBatchEnqueuedTokenLimit, errCode: "ORG_BATCH_ENQUEUED_TOKENS_EXCEEDED"},
	}

	for _, sc := range scopes {
		if sc.limit > 0 && sc.id != "" {
			if l.localBatchSum[sc.key]+estimatedTokens > sc.limit {
				return toQuotaError(sc.errCode)
			}
		}
	}

	for _, sc := range scopes {
		if sc.limit > 0 && sc.id != "" {
			l.localBatchSum[sc.key] += estimatedTokens
		}
	}
	l.localBatchHolds[batchID] = localBatchHold{
		keyID:  idCtx.VirtualKeyID,
		teamID: idCtx.TeamID,
		userID: idCtx.UserID,
		orgID:  effectiveOrgID,
		tokens: estimatedTokens,
	}
	return nil
}

func (l *Limiter) releaseBatchEnqueuedLocal(batchID string) {
	l.localMu.Lock()
	defer l.localMu.Unlock()

	hold, ok := l.localBatchHolds[batchID]
	if !ok {
		return
	}
	scopeKeys := []string{
		"key:" + hold.keyID,
		"team:" + hold.teamID,
		"user:" + hold.userID,
		"org:" + hold.orgID,
	}
	for _, sk := range scopeKeys {
		if cur, exists := l.localBatchSum[sk]; exists {
			next := cur - hold.tokens
			if next <= 0 {
				delete(l.localBatchSum, sk)
			} else {
				l.localBatchSum[sk] = next
			}
		}
	}
	delete(l.localBatchHolds, batchID)
}
