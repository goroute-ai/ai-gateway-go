package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
	"github.com/redis/go-redis/v9"
)

const jwtClaimsAttributePrefix = "jwt_claims."

// AccessRuleEvaluation holds the deterministic result of evaluating active dynamic
// access group rules against an authenticated IdentityContext.
type AccessRuleEvaluation struct {
	MatchedRuleIDs []string
	AccessGroups   []string
	AllowedModels  []string
}

// ValidateAccessGroupRule validates and normalizes an AccessGroupRule prior to persistence.
func ValidateAccessGroupRule(rule *domain.AccessGroupRule) error {
	if rule == nil {
		return fmt.Errorf("access group rule is required")
	}
	rule.Name = strings.TrimSpace(rule.Name)
	if rule.Name == "" {
		return fmt.Errorf("name is required")
	}
	rule.Attribute = strings.TrimSpace(rule.Attribute)
	if !isTrustedAccessRuleAttribute(rule.Attribute) {
		return fmt.Errorf("attribute %q is not a supported trusted attribute (allowed: jwt_claims.<path>, user_id, email, user_role, team_id, issuer)", rule.Attribute)
	}
	rule.Operator = domain.AccessRuleOperator(strings.ToLower(strings.TrimSpace(string(rule.Operator))))
	switch rule.Operator {
	case domain.AccessRuleOperatorEquals,
		domain.AccessRuleOperatorContains,
		domain.AccessRuleOperatorPrefix,
		domain.AccessRuleOperatorInList:
	default:
		return fmt.Errorf("operator %q is unsupported (allowed: equals, contains, prefix, in_list)", rule.Operator)
	}
	rule.Value = strings.TrimSpace(rule.Value)
	if rule.Value == "" {
		return fmt.Errorf("value is required")
	}
	if rule.Operator == domain.AccessRuleOperatorInList && len(parseAccessRuleList(rule.Value)) == 0 {
		return fmt.Errorf("in_list operator requires at least one non-empty value")
	}

	cleanedModels := make([]string, 0, len(rule.AllowedModels))
	seenModels := make(map[string]struct{}, len(rule.AllowedModels))
	for _, m := range rule.AllowedModels {
		trimmed := strings.TrimSpace(m)
		if trimmed == "" {
			continue
		}
		if _, dup := seenModels[trimmed]; dup {
			continue
		}
		seenModels[trimmed] = struct{}{}
		cleanedModels = append(cleanedModels, trimmed)
	}
	rule.AllowedModels = cleanedModels
	rule.AccessGroupID = strings.TrimSpace(rule.AccessGroupID)

	if len(rule.AllowedModels) == 0 && rule.AccessGroupID == "" {
		return fmt.Errorf("at least one allowed_models entry or access_group_id is required")
	}
	return nil
}

func isTrustedAccessRuleAttribute(attr string) bool {
	switch attr {
	case "user_id", "email", "user_role", "team_id", "issuer":
		return true
	}
	if !strings.HasPrefix(attr, jwtClaimsAttributePrefix) {
		return false
	}
	path := strings.TrimPrefix(attr, jwtClaimsAttributePrefix)
	if path == "" || strings.ContainsAny(path, " \t\r\n") {
		return false
	}
	if strings.HasPrefix(path, ".") || strings.HasSuffix(path, ".") || strings.Contains(path, "..") {
		return false
	}
	return true
}

// EvaluateAccessGroupRules evaluates active attribute-based rules against trusted
// Principal / IdentityContext attributes in deterministic priority order (higher priority first).
func EvaluateAccessGroupRules(rules []*domain.AccessGroupRule, idCtx *domain.IdentityContext) AccessRuleEvaluation {
	if idCtx == nil || len(rules) == 0 {
		return AccessRuleEvaluation{}
	}

	ordered := make([]*domain.AccessGroupRule, 0, len(rules))
	for _, r := range rules {
		if r == nil || !r.IsActive {
			continue
		}
		if idCtx.OrgID != "" && r.OrgID != "" && r.OrgID != idCtx.OrgID {
			continue
		}
		ordered = append(ordered, r)
	}
	if len(ordered) == 0 {
		return AccessRuleEvaluation{}
	}

	sort.Slice(ordered, func(i, j int) bool {
		if ordered[i].Priority != ordered[j].Priority {
			return ordered[i].Priority > ordered[j].Priority
		}
		if !ordered[i].CreatedAt.Equal(ordered[j].CreatedAt) {
			return ordered[i].CreatedAt.Before(ordered[j].CreatedAt)
		}
		return ordered[i].ID < ordered[j].ID
	})

	var (
		eval       AccessRuleEvaluation
		seenGroups = make(map[string]struct{})
		seenModels = make(map[string]struct{})
	)
	for _, rule := range ordered {
		values := extractTrustedAttributeValues(idCtx, rule.Attribute)
		if !matchAccessRuleValues(values, rule.Operator, rule.Value) {
			continue
		}
		eval.MatchedRuleIDs = append(eval.MatchedRuleIDs, rule.ID)
		if groupID := strings.TrimSpace(rule.AccessGroupID); groupID != "" {
			if _, ok := seenGroups[groupID]; !ok {
				seenGroups[groupID] = struct{}{}
				eval.AccessGroups = append(eval.AccessGroups, groupID)
			}
		}
		for _, m := range rule.AllowedModels {
			model := strings.TrimSpace(m)
			if model == "" {
				continue
			}
			if _, ok := seenModels[model]; !ok {
				seenModels[model] = struct{}{}
				eval.AllowedModels = append(eval.AllowedModels, model)
			}
		}
	}
	return eval
}

func extractTrustedAttributeValues(idCtx *domain.IdentityContext, attribute string) []string {
	attr := strings.TrimSpace(attribute)
	if idCtx == nil || !isTrustedAccessRuleAttribute(attr) {
		return nil
	}

	switch attr {
	case "user_id":
		if uid := strings.TrimSpace(idCtx.UserID); uid != "" {
			return []string{uid}
		}
		if idCtx.Principal != nil && idCtx.Principal.PrincipalType == "user" {
			if sub := strings.TrimSpace(idCtx.Principal.Subject); sub != "" {
				return []string{sub}
			}
		}
		return nil
	case "email":
		if idCtx.Principal != nil {
			if email := strings.TrimSpace(idCtx.Principal.Email); email != "" {
				return []string{email}
			}
			if idCtx.Principal.RawClaims != nil {
				if raw, ok := idCtx.Principal.RawClaims["email"]; ok {
					return flattenClaimValue(raw)
				}
			}
		}
		return nil
	case "user_role":
		if role := strings.TrimSpace(string(idCtx.Role)); role != "" {
			return []string{role}
		}
		return nil
	case "team_id":
		if teamID := strings.TrimSpace(idCtx.TeamID); teamID != "" {
			return []string{teamID}
		}
		return nil
	case "issuer":
		if idCtx.Principal != nil {
			if iss := strings.TrimSpace(idCtx.Principal.Issuer); iss != "" {
				return []string{iss}
			}
		}
		return nil
	}

	if strings.HasPrefix(attr, jwtClaimsAttributePrefix) {
		if idCtx.Principal == nil || len(idCtx.Principal.RawClaims) == 0 {
			return nil
		}
		claimPath := strings.TrimPrefix(attr, jwtClaimsAttributePrefix)
		rawVal, ok := resolveNestedClaim(idCtx.Principal.RawClaims, claimPath)
		if !ok {
			return nil
		}
		return flattenClaimValue(rawVal)
	}

	return nil
}

func resolveNestedClaim(claims map[string]any, path string) (any, bool) {
	if len(claims) == 0 || path == "" {
		return nil, false
	}
	// First try direct key lookup to support namespaced OIDC claims containing dots.
	if val, ok := claims[path]; ok {
		return val, true
	}
	cur := claims
	remaining := path
	for {
		if val, ok := cur[remaining]; ok {
			return val, true
		}
		dotIdx := strings.IndexByte(remaining, '.')
		if dotIdx <= 0 || dotIdx >= len(remaining)-1 {
			return nil, false
		}
		head := remaining[:dotIdx]
		tail := remaining[dotIdx+1:]
		next, ok := cur[head]
		if !ok {
			return nil, false
		}
		nextMap, ok := next.(map[string]any)
		if !ok {
			return nil, false
		}
		cur = nextMap
		remaining = tail
	}
}

func flattenClaimValue(raw any) []string {
	if raw == nil {
		return nil
	}
	switch v := raw.(type) {
	case string:
		if s := strings.TrimSpace(v); s != "" {
			return []string{s}
		}
	case []string:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s := strings.TrimSpace(item); s != "" {
				out = append(out, s)
			}
		}
		return out
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			out = append(out, flattenScalarClaimValue(item)...)
		}
		return out
	default:
		return flattenScalarClaimValue(v)
	}
	return nil
}

func flattenScalarClaimValue(raw any) []string {
	switch v := raw.(type) {
	case string:
		if s := strings.TrimSpace(v); s != "" {
			return []string{s}
		}
	case bool:
		return []string{strconv.FormatBool(v)}
	case int:
		return []string{strconv.Itoa(v)}
	case int64:
		return []string{strconv.FormatInt(v, 10)}
	case float64:
		return []string{strconv.FormatFloat(v, 'f', -1, 64)}
	case json.Number:
		if s := strings.TrimSpace(v.String()); s != "" {
			return []string{s}
		}
	}
	return nil
}

func matchAccessRuleValues(candidates []string, op domain.AccessRuleOperator, ruleValue string) bool {
	if len(candidates) == 0 {
		return false
	}
	target := strings.TrimSpace(ruleValue)
	if target == "" {
		return false
	}

	switch op {
	case domain.AccessRuleOperatorEquals:
		for _, c := range candidates {
			if c == target {
				return true
			}
		}
		return false
	case domain.AccessRuleOperatorContains:
		for _, c := range candidates {
			if strings.Contains(c, target) {
				return true
			}
		}
		return false
	case domain.AccessRuleOperatorPrefix:
		for _, c := range candidates {
			if strings.HasPrefix(c, target) {
				return true
			}
		}
		return false
	case domain.AccessRuleOperatorInList:
		items := parseAccessRuleList(target)
		if len(items) == 0 {
			return false
		}
		for _, c := range candidates {
			for _, item := range items {
				if c == item {
					return true
				}
			}
		}
		return false
	default:
		return false
	}
}

func parseAccessRuleList(raw string) []string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil
	}
	if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
		var parsed []string
		if err := json.Unmarshal([]byte(trimmed), &parsed); err == nil {
			out := make([]string, 0, len(parsed))
			for _, item := range parsed {
				if v := strings.TrimSpace(item); v != "" {
					out = append(out, v)
				}
			}
			return out
		}
	}
	parts := strings.Split(trimmed, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if v := strings.TrimSpace(p); v != "" {
			out = append(out, v)
		}
	}
	return out
}

func rbacAccessRulesCacheKey(orgID string) string {
	return "gw:rbac:access_rules:" + orgID
}

// InvalidateAccessGroupRules evicts cached dynamic access group rules for orgID across
// L1 memory, L2 Redis, and cross-replica Pub/Sub subscribers.
func (e *RBACEngine) InvalidateAccessGroupRules(ctx context.Context, orgID string) {
	if e == nil || orgID == "" {
		return
	}
	e.ruleCache.Delete(orgID)
	if e.redis != nil {
		_, _ = e.redis.Execute(func(rdb redis.UniversalClient) (any, error) {
			return rdb.Del(ctx, rbacAccessRulesCacheKey(orgID)).Result()
		})
		e.redis.PublishInvalidation(ctx, storage.InvalidationEvent{
			Type:  "rbac_access_rules",
			OrgID: orgID,
		})
	}
}

// StartInvalidationListener subscribes this RBACEngine to Redis Pub/Sub invalidation events
// so standalone RBACEngine instances evict L1 policy and access-rule caches across replicas.
func (e *RBACEngine) StartInvalidationListener(ctx context.Context) {
	if e == nil || e.redis == nil || e.redis.Client() == nil {
		return
	}
	e.invalidationMu.Lock()
	if e.invalidationCancel != nil {
		e.invalidationMu.Unlock()
		return
	}
	listenerCtx, cancel := context.WithCancel(ctx)
	e.invalidationCancel = cancel
	e.invalidationMu.Unlock()

	go func() {
		pubsub := e.redis.Client().Subscribe(listenerCtx, storage.InvalidationChannel)
		defer pubsub.Close()
		if _, err := pubsub.Receive(listenerCtx); err != nil {
			return
		}
		messages := pubsub.Channel()
		for {
			select {
			case <-listenerCtx.Done():
				return
			case msg, ok := <-messages:
				if !ok {
					return
				}
				var ev storage.InvalidationEvent
				if err := json.Unmarshal([]byte(msg.Payload), &ev); err == nil {
					e.HandleInvalidation(ev)
				}
			}
		}
	}()
}

// StopInvalidationListener stops a background Pub/Sub invalidation listener started via StartInvalidationListener.
func (e *RBACEngine) StopInvalidationListener() {
	if e == nil {
		return
	}
	e.invalidationMu.Lock()
	defer e.invalidationMu.Unlock()
	if e.invalidationCancel != nil {
		e.invalidationCancel()
		e.invalidationCancel = nil
	}
}

func (e *RBACEngine) getOrgAccessGroupRules(ctx context.Context, orgID string) ([]*domain.AccessGroupRule, error) {
	if e == nil || orgID == "" || e.repo == nil {
		return nil, nil
	}
	ruleRepo, ok := e.repo.(storage.AccessRuleRepository)
	if !ok || ruleRepo == nil {
		return nil, nil
	}

	now := time.Now().UTC()
	if val, hit := e.ruleCache.Load(orgID); hit {
		entry := val.(cachedAccessRules)
		if now.Before(entry.expiresAt) {
			return entry.rules, nil
		}
		e.ruleCache.Delete(orgID)
	}

	if e.redis != nil {
		res, err := e.redis.Execute(func(rdb redis.UniversalClient) (any, error) {
			return rdb.Get(ctx, rbacAccessRulesCacheKey(orgID)).Result()
		})
		if err == nil {
			if jsonStr, ok := res.(string); ok && jsonStr != "" {
				var rules []*domain.AccessGroupRule
				if json.Unmarshal([]byte(jsonStr), &rules) == nil {
					e.ruleCache.Store(orgID, cachedAccessRules{rules: rules, expiresAt: now.Add(e.cacheTTL)})
					return rules, nil
				}
			}
		}
	}

	rules, err := ruleRepo.ListAccessGroupRules(ctx, orgID, true)
	if err != nil {
		return nil, err
	}
	if rules == nil {
		rules = []*domain.AccessGroupRule{}
	}
	if e.redis != nil {
		if b, mErr := json.Marshal(rules); mErr == nil {
			_, _ = e.redis.Execute(func(rdb redis.UniversalClient) (any, error) {
				return rdb.Set(ctx, rbacAccessRulesCacheKey(orgID), b, e.cacheTTL).Result()
			})
		}
	}
	e.ruleCache.Store(orgID, cachedAccessRules{rules: rules, expiresAt: now.Add(e.cacheTTL)})
	return rules, nil
}

// EvaluateIdentityAccessRules loads active cached access group rules for idCtx.OrgID and
// evaluates them against idCtx's trusted attributes.
func (e *RBACEngine) EvaluateIdentityAccessRules(ctx context.Context, idCtx *domain.IdentityContext) (AccessRuleEvaluation, error) {
	if e == nil || idCtx == nil || idCtx.OrgID == "" {
		return AccessRuleEvaluation{}, nil
	}
	rules, err := e.getOrgAccessGroupRules(ctx, idCtx.OrgID)
	if err != nil {
		return AccessRuleEvaluation{}, err
	}
	return EvaluateAccessGroupRules(rules, idCtx), nil
}

// EnrichIdentityWithAccessRules returns a per-request shallow copy of idCtx populated with
// dynamically granted AccessGroups and DynamicAllowedModels from matching access group rules.
// It never mutates the caller's IdentityContext in place.
func (e *RBACEngine) EnrichIdentityWithAccessRules(ctx context.Context, idCtx *domain.IdentityContext) *domain.IdentityContext {
	if e == nil || idCtx == nil || idCtx.OrgID == "" {
		return idCtx
	}
	eval, err := e.EvaluateIdentityAccessRules(ctx, idCtx)
	if err != nil || (len(eval.AllowedModels) == 0 && len(eval.AccessGroups) == 0) {
		return idCtx
	}
	cp := *idCtx
	cp.DynamicAllowedModels = append([]string(nil), eval.AllowedModels...)
	cp.AccessGroups = append([]string(nil), eval.AccessGroups...)
	return &cp
}
