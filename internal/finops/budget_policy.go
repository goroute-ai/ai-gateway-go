package finops

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/logger"
	"github.com/goroute-ai/ai-gateway-go/internal/security/network"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
	"github.com/redis/go-redis/v9"
)

const (
	defaultSoftBudgetCooldownSec = 3600
	defaultWebhookTimeout        = 5 * time.Second
	defaultRedisDedupTimeout     = 200 * time.Millisecond
)

// SoftBudgetAlert describes a soft-budget threshold crossing event.
type SoftBudgetAlert struct {
	Scope            string    `json:"scope"`
	EntityID         string    `json:"entity_id"`
	OrgID            string    `json:"org_id"`
	SoftBudgetMicros int64     `json:"soft_budget_micros"`
	MaxBudgetMicros  int64     `json:"max_budget_micros"`
	SpentMicros      int64     `json:"spent_micros"`
	ResetPeriod      string    `json:"reset_period"`
	TriggeredAt      time.Time `json:"triggered_at"`
}

// SoftBudgetNotifier emits deduplicated AuditLog entries and async SSRF-checked
// webhook notifications when settled entity spend reaches or exceeds soft_budget_micros.
type SoftBudgetNotifier struct {
	repo        storage.Repository
	redis       *storage.RedisFabric
	httpClient  *http.Client
	webhookURL  string
	cooldownSec int

	localMu    sync.Mutex
	localDedup map[string]time.Time
	wg         sync.WaitGroup
}

// NewSoftBudgetNotifier constructs a SoftBudgetNotifier using network.NewHTTPClient(netPolicy)
// for outbound webhook delivery.
func NewSoftBudgetNotifier(
	repo storage.Repository,
	redisFabric *storage.RedisFabric,
	netPolicy *network.Policy,
	webhookURL string,
	cooldownSec int,
) *SoftBudgetNotifier {
	if netPolicy == nil {
		if pol, err := network.NewPolicy(config.OutboundSSRFConfig{}); err == nil {
			netPolicy = pol
		}
	}
	if cooldownSec <= 0 {
		cooldownSec = defaultSoftBudgetCooldownSec
	}
	return &SoftBudgetNotifier{
		repo:        repo,
		redis:       redisFabric,
		httpClient:  network.NewHTTPClient(netPolicy),
		webhookURL:  strings.TrimSpace(webhookURL),
		cooldownSec: cooldownSec,
		localDedup:  make(map[string]time.Time),
	}
}

// SoftBudgetAlertKey returns the cluster-slot-aligned Redis deduplication key
// for a soft-budget alert scoped by (org, scope, entity, reset_period).
func SoftBudgetAlertKey(orgID, scope, entityID, resetPeriod string) string {
	orgTag := strings.TrimSpace(orgID)
	if orgTag == "" {
		orgTag = "default"
	}
	period := strings.TrimSpace(resetPeriod)
	if period == "" {
		period = string(domain.BudgetResetMonthly)
	}
	return fmt.Sprintf("gw:budget:soft_alert:{org:%s}:%s:%s:%s", orgTag, strings.TrimSpace(scope), strings.TrimSpace(entityID), period)
}

// CheckAndNotifyForEvents inspects settled entities touched by events and triggers
// soft-budget alerts for any scope whose settled spend >= soft_budget_micros.
func (n *SoftBudgetNotifier) CheckAndNotifyForEvents(ctx context.Context, events []domain.SpendEvent) {
	if n == nil || n.repo == nil || len(events) == 0 {
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}

	seenKeys := make(map[string]struct{})
	seenUsers := make(map[string]string) // userID -> orgID
	seenTeams := make(map[string]struct{})
	seenOrgs := make(map[string]struct{})

	for _, ev := range events {
		if ev.CostMicros <= 0 {
			continue
		}
		if ev.VirtualKeyID != "" {
			seenKeys[ev.VirtualKeyID] = struct{}{}
		}
		if ev.UserID != "" {
			seenUsers[ev.UserID] = ev.OrgID
		}
		if ev.TeamID != "" {
			seenTeams[ev.TeamID] = struct{}{}
		}
		if ev.OrgID != "" {
			seenOrgs[ev.OrgID] = struct{}{}
		}
	}

	for keyID := range seenKeys {
		vk, err := n.repo.GetVirtualKeyByID(ctx, keyID)
		if err != nil || vk == nil || vk.SoftBudgetMicros <= 0 || vk.SpentMicros < vk.SoftBudgetMicros {
			continue
		}
		n.NotifyIfExceeded(ctx, SoftBudgetAlert{
			Scope:            "key",
			EntityID:         vk.ID,
			OrgID:            vk.OrgID,
			SoftBudgetMicros: vk.SoftBudgetMicros,
			MaxBudgetMicros:  vk.MaxBudgetMicros,
			SpentMicros:      vk.SpentMicros,
			ResetPeriod:      string(vk.BudgetResetPeriod),
		})
	}

	for userID, orgID := range seenUsers {
		user := n.lookupUser(ctx, orgID, userID)
		if user == nil || user.SoftBudgetMicros <= 0 || user.SpentMicros < user.SoftBudgetMicros {
			continue
		}
		n.NotifyIfExceeded(ctx, SoftBudgetAlert{
			Scope:            "user",
			EntityID:         user.ID,
			OrgID:            user.OrgID,
			SoftBudgetMicros: user.SoftBudgetMicros,
			MaxBudgetMicros:  user.MaxBudgetMicros,
			SpentMicros:      user.SpentMicros,
			ResetPeriod:      string(user.BudgetResetPeriod),
		})
	}

	for teamID := range seenTeams {
		team, err := n.repo.GetTeam(ctx, teamID)
		if err != nil || team == nil || team.SoftBudgetMicros <= 0 || team.SpentMicros < team.SoftBudgetMicros {
			continue
		}
		n.NotifyIfExceeded(ctx, SoftBudgetAlert{
			Scope:            "team",
			EntityID:         team.ID,
			OrgID:            team.OrgID,
			SoftBudgetMicros: team.SoftBudgetMicros,
			MaxBudgetMicros:  team.MaxBudgetMicros,
			SpentMicros:      team.SpentMicros,
			ResetPeriod:      string(team.BudgetResetPeriod),
		})
	}

	for orgID := range seenOrgs {
		org, err := n.repo.GetOrganization(ctx, orgID)
		if err != nil || org == nil || org.SoftBudgetMicros <= 0 || org.SpentMicros < org.SoftBudgetMicros {
			continue
		}
		n.NotifyIfExceeded(ctx, SoftBudgetAlert{
			Scope:            "org",
			EntityID:         org.ID,
			OrgID:            org.ID,
			SoftBudgetMicros: org.SoftBudgetMicros,
			MaxBudgetMicros:  org.MaxBudgetMicros,
			SpentMicros:      org.SpentMicros,
			ResetPeriod:      string(org.BudgetResetPeriod),
		})
	}
}

func (n *SoftBudgetNotifier) lookupUser(ctx context.Context, orgID, userID string) *domain.User {
	if ul, ok := n.repo.(storage.UserLookupRepository); ok {
		if u, err := ul.GetUser(ctx, userID); err == nil && u != nil {
			return u
		}
	}
	if orgID != "" {
		if users, err := n.repo.ListUsers(ctx, orgID); err == nil {
			for _, u := range users {
				if u != nil && u.ID == userID {
					return u
				}
			}
		}
	}
	return nil
}

// NotifyIfExceeded emits an AuditLog entry and async webhook notification when
// alert.SoftBudgetMicros > 0 and alert.SpentMicros >= alert.SoftBudgetMicros,
// subject to per-(scope, entity_id, reset_period) cooldown deduplication.
// Returns true if an alert was newly emitted.
func (n *SoftBudgetNotifier) NotifyIfExceeded(ctx context.Context, alert SoftBudgetAlert) bool {
	if n == nil || alert.SoftBudgetMicros <= 0 || alert.SpentMicros < alert.SoftBudgetMicros {
		return false
	}
	if alert.Scope == "" || alert.EntityID == "" {
		return false
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if alert.ResetPeriod == "" {
		alert.ResetPeriod = string(domain.BudgetResetMonthly)
	}
	if alert.TriggeredAt.IsZero() {
		alert.TriggeredAt = time.Now().UTC()
	}

	dedupKey := SoftBudgetAlertKey(alert.OrgID, alert.Scope, alert.EntityID, alert.ResetPeriod)
	if !n.acquireCooldown(ctx, dedupKey) {
		return false
	}

	if n.repo != nil {
		if err := n.repo.RecordAuditLog(ctx, &domain.AuditLog{
			OrgID:      alert.OrgID,
			ActorID:    "system:finops",
			Action:     "budget.soft_limit_reached",
			Resource:   auditResourceForScope(alert.Scope),
			ResourceID: alert.EntityID,
			Details: map[string]any{
				"scope":              alert.Scope,
				"soft_budget_micros": alert.SoftBudgetMicros,
				"max_budget_micros":  alert.MaxBudgetMicros,
				"spent_micros":       alert.SpentMicros,
				"reset_period":       alert.ResetPeriod,
				"webhook_configured": n.webhookURL != "",
			},
			CreatedAt: alert.TriggeredAt,
		}); err != nil {
			logger.Warn("Failed to record soft budget audit log",
				slog.String("component", "finops"),
				slog.String("scope", alert.Scope),
				slog.String("entity_id", alert.EntityID),
				slog.String("error", err.Error()),
			)
		}
	}

	if n.webhookURL != "" && n.httpClient != nil {
		payload, err := json.Marshal(alert)
		if err != nil {
			logger.Warn("Failed to marshal soft budget webhook payload",
				slog.String("component", "finops"),
				slog.String("error", err.Error()),
			)
			return true
		}
		n.wg.Add(1)
		go func(body []byte, a SoftBudgetAlert) {
			defer n.wg.Done()
			reqCtx, cancel := context.WithTimeout(context.Background(), defaultWebhookTimeout)
			defer cancel()
			req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, n.webhookURL, bytes.NewReader(body))
			if err != nil {
				logger.Warn("Failed to build soft budget webhook request",
					slog.String("component", "finops"),
					slog.String("scope", a.Scope),
					slog.String("entity_id", a.EntityID),
					slog.String("error", err.Error()),
				)
				return
			}
			req.Header.Set("Content-Type", "application/json")
			resp, err := n.httpClient.Do(req)
			if err != nil {
				logger.Warn("Soft budget webhook delivery failed",
					slog.String("component", "finops"),
					slog.String("scope", a.Scope),
					slog.String("entity_id", a.EntityID),
					slog.String("error", err.Error()),
				)
				return
			}
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
			_ = resp.Body.Close()
			if resp.StatusCode >= http.StatusBadRequest {
				logger.Warn("Soft budget webhook returned non-success status",
					slog.String("component", "finops"),
					slog.String("scope", a.Scope),
					slog.String("entity_id", a.EntityID),
					slog.Int("status_code", resp.StatusCode),
				)
			}
		}(payload, alert)
	}

	return true
}

// ClearCooldown removes the deduplication marker for a scope after a budget period reset.
func (n *SoftBudgetNotifier) ClearCooldown(ctx context.Context, orgID, scope, entityID, resetPeriod string) {
	if n == nil || scope == "" || entityID == "" {
		return
	}
	dedupKey := SoftBudgetAlertKey(orgID, scope, entityID, resetPeriod)
	n.localMu.Lock()
	delete(n.localDedup, dedupKey)
	n.localMu.Unlock()
	if n.redis != nil && n.redis.Client() != nil {
		if ctx == nil {
			ctx = context.Background()
		}
		_, _ = n.redis.Execute(func(rdb redis.UniversalClient) (any, error) {
			rCtx, cancel := context.WithTimeout(ctx, defaultRedisDedupTimeout)
			defer cancel()
			return rdb.Del(rCtx, dedupKey).Result()
		})
	}
}

// Wait blocks until all in-flight async webhook deliveries complete or ctx expires.
func (n *SoftBudgetNotifier) Wait(ctx context.Context) error {
	if n == nil {
		return nil
	}
	done := make(chan struct{})
	go func() {
		n.wg.Wait()
		close(done)
	}()
	if ctx == nil {
		<-done
		return nil
	}
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (n *SoftBudgetNotifier) acquireCooldown(ctx context.Context, dedupKey string) bool {
	ttl := time.Duration(n.cooldownSec) * time.Second
	if n.redis != nil && n.redis.Client() != nil {
		res, err := n.redis.Execute(func(rdb redis.UniversalClient) (any, error) {
			rCtx, cancel := context.WithTimeout(ctx, defaultRedisDedupTimeout)
			defer cancel()
			return rdb.SetNX(rCtx, dedupKey, "1", ttl).Result()
		})
		if err == nil {
			if acquired, ok := res.(bool); ok {
				return acquired
			}
		}
	}

	now := time.Now().UTC()
	n.localMu.Lock()
	defer n.localMu.Unlock()
	if exp, exists := n.localDedup[dedupKey]; exists && now.Before(exp) {
		return false
	}
	if len(n.localDedup) >= 16384 {
		for k, exp := range n.localDedup {
			if !now.Before(exp) {
				delete(n.localDedup, k)
			}
		}
	}
	n.localDedup[dedupKey] = now.Add(ttl)
	return true
}

func auditResourceForScope(scope string) string {
	switch scope {
	case "org":
		return "organization"
	case "key":
		return "virtual_key"
	default:
		return scope
	}
}

func scaleThrottleLimit(limit int, throttlePct float64) int {
	if limit <= 0 {
		return 0
	}
	scaled := int(float64(limit) * throttlePct)
	if scaled < 1 {
		return 1
	}
	return scaled
}

// ApplyBudgetThrottle scales RPM and TPM limits down to max(1, int(float64(limit)*throttlePct))
// for any scope where ThrottleOnBudgetExceeded is enabled and SpentMicros >= MaxBudgetMicros
// (with MaxBudgetMicros > 0). For throttled scopes, MaxBudgetMicros is cleared on the returned
// effective IdentityContext so downstream rate-limit admission enforces throttled RPM/TPM
// instead of hard-blocking on budget exhaustion.
func ApplyBudgetThrottle(idCtx *domain.IdentityContext, throttlePct float64) (*domain.IdentityContext, bool) {
	if idCtx == nil {
		return nil, false
	}
	if throttlePct < 0 {
		throttlePct = 0
	} else if throttlePct > 1 {
		throttlePct = 1
	}

	keyThrottle := idCtx.KeyThrottleOnBudgetExceeded && idCtx.KeyMaxBudgetMicros > 0 && idCtx.KeySpentMicros >= idCtx.KeyMaxBudgetMicros
	teamThrottle := idCtx.TeamThrottleOnBudgetExceeded && idCtx.TeamMaxBudgetMicros > 0 && idCtx.TeamSpentMicros >= idCtx.TeamMaxBudgetMicros
	userThrottle := idCtx.UserThrottleOnBudgetExceeded && idCtx.UserMaxBudgetMicros > 0 && idCtx.UserSpentMicros >= idCtx.UserMaxBudgetMicros
	orgThrottle := idCtx.OrgThrottleOnBudgetExceeded && idCtx.OrgMaxBudgetMicros > 0 && idCtx.OrgSpentMicros >= idCtx.OrgMaxBudgetMicros

	if !keyThrottle && !teamThrottle && !userThrottle && !orgThrottle {
		return idCtx, false
	}

	eff := *idCtx
	if keyThrottle {
		eff.KeyMaxBudgetMicros = 0
		eff.KeyRPMLimit = scaleThrottleLimit(eff.KeyRPMLimit, throttlePct)
		eff.KeyTPMLimit = scaleThrottleLimit(eff.KeyTPMLimit, throttlePct)
	}
	if teamThrottle {
		eff.TeamMaxBudgetMicros = 0
		eff.TeamRPMLimit = scaleThrottleLimit(eff.TeamRPMLimit, throttlePct)
		eff.TeamTPMLimit = scaleThrottleLimit(eff.TeamTPMLimit, throttlePct)
	}
	if userThrottle {
		eff.UserMaxBudgetMicros = 0
		eff.UserRPMLimit = scaleThrottleLimit(eff.UserRPMLimit, throttlePct)
		eff.UserTPMLimit = scaleThrottleLimit(eff.UserTPMLimit, throttlePct)
	}
	if orgThrottle {
		eff.OrgMaxBudgetMicros = 0
		eff.OrgRPMLimit = scaleThrottleLimit(eff.OrgRPMLimit, throttlePct)
		eff.OrgTPMLimit = scaleThrottleLimit(eff.OrgTPMLimit, throttlePct)
	}
	return &eff, true
}

// BudgetCheckFunc checks whether candidateModel is within budget for the current request.
// Returning nil means candidateModel can be admitted.
type BudgetCheckFunc func(ctx context.Context, candidateModel string) error

// ResolveBudgetFallbackModel inspects BudgetFallbacks[requestedModel] in Key -> Team -> User -> Org
// precedence order and returns the first candidate model for which budgetCheckFn returns nil.
func ResolveBudgetFallbackModel(
	ctx context.Context,
	idCtx *domain.IdentityContext,
	requestedModel string,
	budgetCheckFn BudgetCheckFunc,
) (string, bool) {
	if idCtx == nil || budgetCheckFn == nil {
		return "", false
	}
	requested := strings.TrimSpace(requestedModel)
	if requested == "" {
		return "", false
	}

	scopeMaps := []map[string][]string{
		idCtx.KeyBudgetFallbacks,
		idCtx.TeamBudgetFallbacks,
		idCtx.UserBudgetFallbacks,
		idCtx.OrgBudgetFallbacks,
	}

	seen := map[string]struct{}{
		requested: {},
	}
	for _, m := range scopeMaps {
		if len(m) == 0 {
			continue
		}
		for _, rawCandidate := range m[requested] {
			candidate := strings.TrimSpace(rawCandidate)
			if candidate == "" {
				continue
			}
			if _, dup := seen[candidate]; dup {
				continue
			}
			seen[candidate] = struct{}{}
			if err := budgetCheckFn(ctx, candidate); err == nil {
				return candidate, true
			}
		}
	}
	return "", false
}
