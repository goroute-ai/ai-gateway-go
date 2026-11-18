package router

import (
	"context"
	"fmt"
	"math"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
	"github.com/redis/go-redis/v9"
)

const (
	defaultSaturationThreshold  = 0.80
	defaultActiveCallerTTL      = 60 * time.Second
	defaultPriorityWindow       = 60 * time.Second
	defaultPriorityRedisTimeout = 50 * time.Millisecond
	defaultBorrowMultiple       = 2.0
	defaultPriorityClassWeight  = 1.0
	defaultPriorityClassName    = "default"
)

// CapacityMode describes whether dynamic priority capacity sharing is currently
// allowing idle-capacity borrowing (generous) or enforcing strict normalized weights.
type CapacityMode string

const (
	CapacityModeGenerous CapacityMode = "generous"
	CapacityModeStrict   CapacityMode = "strict"
)

// DynamicPriorityConfig configures saturation-aware dynamic priority capacity sharing
// and PTU team share enforcement.
type DynamicPriorityConfig struct {
	Enabled               bool
	SaturationThreshold   float64
	ActiveCallerTTL       time.Duration
	WindowDuration        time.Duration
	RedisTimeout          time.Duration
	DefaultWeight         float64
	DefaultBorrowMultiple float64
}

func normalizeDynamicPriorityConfig(cfg DynamicPriorityConfig) DynamicPriorityConfig {
	if cfg.SaturationThreshold <= 0 || cfg.SaturationThreshold > 1 {
		cfg.SaturationThreshold = defaultSaturationThreshold
	}
	if cfg.ActiveCallerTTL <= 0 {
		cfg.ActiveCallerTTL = defaultActiveCallerTTL
	}
	if cfg.WindowDuration <= 0 {
		cfg.WindowDuration = defaultPriorityWindow
	}
	if cfg.RedisTimeout <= 0 {
		cfg.RedisTimeout = defaultPriorityRedisTimeout
	}
	if cfg.DefaultWeight <= 0 {
		cfg.DefaultWeight = defaultPriorityClassWeight
	}
	if cfg.DefaultBorrowMultiple <= 0 {
		cfg.DefaultBorrowMultiple = defaultBorrowMultiple
	}
	return cfg
}

var activeCallerRegisterScript = redis.NewScript(`
local nowMs = tonumber(ARGV[1]) or 0
local minScoreMs = tonumber(ARGV[2]) or 0
local callerID = ARGV[3]
local className = ARGV[4]
local ttlSec = tonumber(ARGV[5]) or 120

local expired = redis.call("ZRANGEBYSCORE", KEYS[1], "-inf", minScoreMs)
for i = 1, #expired, 1000 do
	local last = math.min(i + 999, #expired)
	redis.call("ZREM", KEYS[1], unpack(expired, i, last))
	redis.call("HDEL", KEYS[2], unpack(expired, i, last))
end

redis.call("ZADD", KEYS[1], nowMs, callerID)
redis.call("HSET", KEYS[2], callerID, className)
if ttlSec > 0 then
	redis.call("EXPIRE", KEYS[1], ttlSec)
	redis.call("EXPIRE", KEYS[2], ttlSec)
end

local members = redis.call("ZRANGE", KEYS[1], 0, -1)
if #members == 0 then
	return {}
end
local out = {}
for i = 1, #members, 1000 do
	local last = math.min(i + 999, #members)
	local vals = redis.call("HMGET", KEYS[2], unpack(members, i, last))
	for j = 1, #vals do
		out[#out + 1] = vals[j] or ""
	end
end
return out
`)

var activeCallerReadScript = redis.NewScript(`
local minScoreMs = tonumber(ARGV[1]) or 0
local expired = redis.call("ZRANGEBYSCORE", KEYS[1], "-inf", minScoreMs)
for i = 1, #expired, 1000 do
	local last = math.min(i + 999, #expired)
	redis.call("ZREM", KEYS[1], unpack(expired, i, last))
	redis.call("HDEL", KEYS[2], unpack(expired, i, last))
end

local members = redis.call("ZRANGE", KEYS[1], 0, -1)
if #members == 0 then
	return {}
end
local out = {}
for i = 1, #members, 1000 do
	local last = math.min(i + 999, #members)
	local vals = redis.call("HMGET", KEYS[2], unpack(members, i, last))
	for j = 1, #vals do
		out[#out + 1] = vals[j] or ""
	end
end
return out
`)

var acquireWindowRateScript = redis.NewScript(`
local limRPM = tonumber(ARGV[1]) or 0
local limTPM = tonumber(ARGV[2]) or 0
local est = tonumber(ARGV[3]) or 0
local ttl = tonumber(ARGV[4]) or 120

local curRPM = tonumber(redis.call("GET", KEYS[1]) or "0") or 0
local curTPM = tonumber(redis.call("GET", KEYS[2]) or "0") or 0

if limRPM > 0 and (curRPM + 1) > limRPM then
	return {0, "rpm", curRPM, curTPM}
end
if limTPM > 0 and ((est > 0 and (curTPM + est) > limTPM) or (est == 0 and curTPM >= limTPM)) then
	return {0, "tpm", curRPM, curTPM}
end

local newRPM = redis.call("INCR", KEYS[1])
if ttl > 0 and redis.call("TTL", KEYS[1]) < 0 then
	redis.call("EXPIRE", KEYS[1], ttl)
end

local newTPM = curTPM
if est > 0 then
	newTPM = redis.call("INCRBY", KEYS[2], est)
	if ttl > 0 and redis.call("TTL", KEYS[2]) < 0 then
		redis.call("EXPIRE", KEYS[2], ttl)
	end
end
return {1, "", newRPM, newTPM}
`)

var reconcileWindowTokensScript = redis.NewScript(`
local delta = tonumber(ARGV[1]) or 0
if delta == 0 then
	return tonumber(redis.call("GET", KEYS[1]) or "0") or 0
end
local updated = redis.call("INCRBY", KEYS[1], delta)
if updated < 0 then
	redis.call("SET", KEYS[1], 0)
	updated = 0
end
local ttl = tonumber(ARGV[2]) or 120
if ttl > 0 and redis.call("TTL", KEYS[1]) < 0 then
	redis.call("EXPIRE", KEYS[1], ttl)
end
return updated
`)

// ActiveCallersKey returns the Redis Cluster slot-aligned sorted-set key tracking
// active callers (teams/keys) per model within an organization.
func ActiveCallersKey(orgID, model string) string {
	return fmt.Sprintf("gw:cap:%s:active:%s", orgClusterHashTag(orgID), normalizeCapKeySegment(model))
}

func activeCallerClassesKey(orgID, model string) string {
	return fmt.Sprintf("gw:cap:%s:active_classes:%s", orgClusterHashTag(orgID), normalizeCapKeySegment(model))
}

// PriorityCallerRPMKey returns the Redis Cluster slot-aligned RPM usage key for dynamic priority limiting.
func PriorityCallerRPMKey(orgID, model, callerID string, bucket int64) string {
	return fmt.Sprintf("gw:cap:%s:usage:%s:caller:%s:rpm:%d", orgClusterHashTag(orgID), normalizeCapKeySegment(model), normalizeCapKeySegment(callerID), bucket)
}

// PriorityCallerTPMKey returns the Redis Cluster slot-aligned TPM usage key for dynamic priority limiting.
func PriorityCallerTPMKey(orgID, model, callerID string, bucket int64) string {
	return fmt.Sprintf("gw:cap:%s:usage:%s:caller:%s:tpm:%d", orgClusterHashTag(orgID), normalizeCapKeySegment(model), normalizeCapKeySegment(callerID), bucket)
}

// PTUTeamRPMKey returns the Redis Cluster slot-aligned RPM usage key for a deployment's PTU team share.
func PTUTeamRPMKey(orgID, depID, teamID string, bucket int64) string {
	return fmt.Sprintf("gw:ptu:%s:dep:%s:team:%s:rpm:%d", orgClusterHashTag(orgID), normalizeCapKeySegment(depID), normalizeCapKeySegment(teamID), bucket)
}

// PTUTeamTPMKey returns the Redis Cluster slot-aligned TPM usage key for a deployment's PTU team share.
func PTUTeamTPMKey(orgID, depID, teamID string, bucket int64) string {
	return fmt.Sprintf("gw:ptu:%s:dep:%s:team:%s:tpm:%d", orgClusterHashTag(orgID), normalizeCapKeySegment(depID), normalizeCapKeySegment(teamID), bucket)
}

func normalizeCapKeySegment(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "_default"
	}
	return s
}

type activeCallerEntry struct {
	className string
	lastSeen  time.Time
}

// ActiveTenantRegistry tracks active callers (teams/keys) per model using Redis
// sorted sets with sliding TTLs and an in-memory fallback when Redis is absent or degraded.
type ActiveTenantRegistry struct {
	redis        *storage.RedisFabric
	ttl          time.Duration
	redisTimeout time.Duration
	nowFn        func() time.Time

	mu      sync.Mutex
	entries map[string]map[string]activeCallerEntry // key: orgID + "\x00" + model
}

// NewActiveTenantRegistry constructs an ActiveTenantRegistry with the given sliding TTL.
func NewActiveTenantRegistry(redisFabric *storage.RedisFabric, ttl time.Duration) *ActiveTenantRegistry {
	if ttl <= 0 {
		ttl = defaultActiveCallerTTL
	}
	return &ActiveTenantRegistry{
		redis:        redisFabric,
		ttl:          ttl,
		redisTimeout: defaultPriorityRedisTimeout,
		nowFn:        time.Now,
		entries:      make(map[string]map[string]activeCallerEntry),
	}
}

// SetNowFunc overrides the clock function used for sliding TTL expiry (intended for tests).
func (r *ActiveTenantRegistry) SetNowFunc(fn func() time.Time) {
	if r == nil || fn == nil {
		return
	}
	r.mu.Lock()
	r.nowFn = fn
	r.mu.Unlock()
}

func (r *ActiveTenantRegistry) currentNow() time.Time {
	r.mu.Lock()
	fn := r.nowFn
	r.mu.Unlock()
	if fn != nil {
		return fn().UTC()
	}
	return time.Now().UTC()
}

// Register records or refreshes callerID as active on model under priorityClass,
// pruning expired entries and returning active counts by class.
func (r *ActiveTenantRegistry) Register(ctx context.Context, orgID, model, callerID, priorityClass string) (int, map[string]int, error) {
	if r == nil {
		return 0, nil, nil
	}
	callerID = strings.TrimSpace(callerID)
	if callerID == "" {
		callerID = "_anonymous"
	}
	priorityClass = normalizeClassName(priorityClass)
	model = strings.TrimSpace(model)
	now := r.currentNow()

	if r.redis != nil && r.redis.Client() != nil {
		if ctx == nil {
			ctx = context.Background()
		}
		rCtx, cancel := context.WithTimeout(ctx, r.redisTimeout)
		defer cancel()

		nowMs := now.UnixMilli()
		minScoreMs := now.Add(-r.ttl).UnixMilli()
		expireSec := int64(math.Ceil(r.ttl.Seconds())) * 2
		if expireSec < 2 {
			expireSec = 2
		}
		res, err := r.redis.Execute(func(rdb redis.UniversalClient) (any, error) {
			return activeCallerRegisterScript.Run(
				rCtx,
				rdb,
				[]string{ActiveCallersKey(orgID, model), activeCallerClassesKey(orgID, model)},
				nowMs, minScoreMs, callerID, priorityClass, expireSec,
			).Result()
		})
		if err == nil {
			total, byClass := parseActiveClassList(res)
			r.registerLocal(orgID, model, callerID, priorityClass, now)
			return total, byClass, nil
		}
	}

	total, byClass := r.registerLocal(orgID, model, callerID, priorityClass, now)
	return total, byClass, nil
}

// ActiveCounts returns the active caller count and per-class breakdown for (orgID, model)
// after pruning entries older than the sliding TTL.
func (r *ActiveTenantRegistry) ActiveCounts(ctx context.Context, orgID, model string) (int, map[string]int, error) {
	if r == nil {
		return 0, nil, nil
	}
	model = strings.TrimSpace(model)
	now := r.currentNow()

	if r.redis != nil && r.redis.Client() != nil {
		if ctx == nil {
			ctx = context.Background()
		}
		rCtx, cancel := context.WithTimeout(ctx, r.redisTimeout)
		defer cancel()

		minScoreMs := now.Add(-r.ttl).UnixMilli()
		res, err := r.redis.Execute(func(rdb redis.UniversalClient) (any, error) {
			return activeCallerReadScript.Run(
				rCtx,
				rdb,
				[]string{ActiveCallersKey(orgID, model), activeCallerClassesKey(orgID, model)},
				minScoreMs,
			).Result()
		})
		if err == nil {
			total, byClass := parseActiveClassList(res)
			return total, byClass, nil
		}
	}

	total, byClass := r.countsLocal(orgID, model, now)
	return total, byClass, nil
}

// ActiveCallerCount returns the total number of non-expired active callers for (orgID, model).
func (r *ActiveTenantRegistry) ActiveCallerCount(ctx context.Context, orgID, model string) (int, error) {
	total, _, err := r.ActiveCounts(ctx, orgID, model)
	return total, err
}

func (r *ActiveTenantRegistry) registerLocal(orgID, model, callerID, priorityClass string, now time.Time) (int, map[string]int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	key := orgID + "\x00" + model
	m := r.entries[key]
	if m == nil {
		m = make(map[string]activeCallerEntry)
		r.entries[key] = m
	}
	cutoff := now.Add(-r.ttl)
	for id, entry := range m {
		if !entry.lastSeen.After(cutoff) {
			delete(m, id)
		}
	}
	m[callerID] = activeCallerEntry{
		className: priorityClass,
		lastSeen:  now,
	}
	return summarizeActiveMap(m)
}

func (r *ActiveTenantRegistry) countsLocal(orgID, model string, now time.Time) (int, map[string]int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	key := orgID + "\x00" + model
	m := r.entries[key]
	if len(m) == 0 {
		return 0, map[string]int{}
	}
	cutoff := now.Add(-r.ttl)
	for id, entry := range m {
		if !entry.lastSeen.After(cutoff) {
			delete(m, id)
		}
	}
	if len(m) == 0 {
		delete(r.entries, key)
		return 0, map[string]int{}
	}
	return summarizeActiveMap(m)
}

func summarizeActiveMap(m map[string]activeCallerEntry) (int, map[string]int) {
	byClass := make(map[string]int, len(m))
	for _, entry := range m {
		cls := normalizeClassName(entry.className)
		byClass[cls]++
	}
	return len(m), byClass
}

func parseActiveClassList(res any) (int, map[string]int) {
	byClass := make(map[string]int)
	slice, ok := res.([]any)
	if !ok {
		return 0, byClass
	}
	total := 0
	for _, item := range slice {
		cls := ""
		if s, ok := item.(string); ok {
			cls = s
		}
		cls = normalizeClassName(cls)
		byClass[cls]++
		total++
	}
	return total, byClass
}

func normalizeClassName(name string) string {
	trimmed := strings.TrimSpace(name)
	if trimmed == "" {
		return defaultPriorityClassName
	}
	return trimmed
}

// ComputeSaturation computes real-time saturation as max(usedRPM/capRPM, usedTPM/capTPM).
func ComputeSaturation(usedRPM, capRPM, usedTPM, capTPM int) float64 {
	var sat float64
	if capRPM > 0 && usedRPM > 0 {
		if r := float64(usedRPM) / float64(capRPM); r > sat {
			sat = r
		}
	}
	if capTPM > 0 && usedTPM > 0 {
		if t := float64(usedTPM) / float64(capTPM); t > sat {
			sat = t
		}
	}
	if sat < 0 {
		return 0
	}
	return sat
}

// PriorityCapacityRequest describes a caller's capacity-sharing evaluation/admission inputs.
type PriorityCapacityRequest struct {
	OrgID           string
	Model           string
	CallerID        string
	PriorityClass   string
	BaseRPM         int
	BaseTPM         int
	CapRPM          int
	CapTPM          int
	UsedRPM         int
	UsedTPM         int
	EstimatedTokens int
	KnownClasses    map[string]*domain.PriorityClass
}

// PriorityAllowance reports the computed capacity-sharing mode and effective limits
// for a caller under current model/deployment saturation.
type PriorityAllowance struct {
	Mode                 CapacityMode `json:"mode"`
	Saturation           float64      `json:"saturation"`
	SaturationThreshold  float64      `json:"saturation_threshold"`
	PriorityClass        string       `json:"priority_class"`
	NormalizedWeight     float64      `json:"normalized_weight"`
	ActiveCallersTotal   int          `json:"active_callers_total"`
	ActiveCallersInClass int          `json:"active_callers_in_class"`
	EffectiveRPM         int          `json:"effective_rpm"`
	EffectiveTPM         int          `json:"effective_tpm"`
	UsedCallerRPM        int          `json:"used_caller_rpm"`
	UsedCallerTPM        int          `json:"used_caller_tpm"`
	Allowed              bool         `json:"allowed"`
}

// PTUDeploymentAllocation summarizes a deployment's PTU team share reservations
// relative to a requesting team.
type PTUDeploymentAllocation struct {
	DeploymentID          string
	TeamShare             *domain.DeploymentPTUShare
	TotalReservedRPM      int
	TotalReservedTPM      int
	OtherTeamsReservedRPM int
	OtherTeamsReservedTPM int
	AvailableRPMForTeam   int // 0 if deployment has no RPMCapacity configured
	AvailableTPMForTeam   int // 0 if deployment has no TPMCapacity configured
	HasAnyShares          bool
}

// PTUShareCheckResult reports the outcome of per-team PTU share rate-limit enforcement.
type PTUShareCheckResult struct {
	HasShare    bool `json:"has_share"`
	Allowed     bool `json:"allowed"`
	ReservedRPM int  `json:"reserved_rpm"`
	ReservedTPM int  `json:"reserved_tpm"`
	UsedRPM     int  `json:"used_rpm"`
	UsedTPM     int  `json:"used_tpm"`
}

type localWindowCounter struct {
	bucket int64
	rpm    int
	tpm    int
}

// DynamicPriorityLimiter implements saturation-aware dynamic priority capacity sharing
// across active callers and enforces dedicated PTU team shares on deployments.
type DynamicPriorityLimiter struct {
	cfg      DynamicPriorityConfig
	redis    *storage.RedisFabric
	registry *ActiveTenantRegistry
	ptuRepo  storage.PTUShareRepository
	nowFn    func() time.Time

	localMu            sync.Mutex
	localPriorityUsage map[string]*localWindowCounter
	localPTUUsage      map[string]*localWindowCounter
}

// NewDynamicPriorityLimiter creates a DynamicPriorityLimiter with optional Redis and PTU repository backing.
func NewDynamicPriorityLimiter(
	redisFabric *storage.RedisFabric,
	ptuRepo storage.PTUShareRepository,
	cfg ...DynamicPriorityConfig,
) *DynamicPriorityLimiter {
	var c DynamicPriorityConfig
	if len(cfg) > 0 {
		c = cfg[0]
	}
	c = normalizeDynamicPriorityConfig(c)
	return &DynamicPriorityLimiter{
		cfg:                c,
		redis:              redisFabric,
		registry:           NewActiveTenantRegistry(redisFabric, c.ActiveCallerTTL),
		ptuRepo:            ptuRepo,
		nowFn:              time.Now,
		localPriorityUsage: make(map[string]*localWindowCounter),
		localPTUUsage:      make(map[string]*localWindowCounter),
	}
}

// Registry returns the underlying ActiveTenantRegistry.
func (d *DynamicPriorityLimiter) Registry() *ActiveTenantRegistry {
	if d == nil {
		return nil
	}
	return d.registry
}

// SetNowFunc overrides the clock for deterministic window/TTL testing.
func (d *DynamicPriorityLimiter) SetNowFunc(fn func() time.Time) {
	if d == nil || fn == nil {
		return
	}
	d.localMu.Lock()
	d.nowFn = fn
	d.localMu.Unlock()
	if d.registry != nil {
		d.registry.SetNowFunc(fn)
	}
}

func (d *DynamicPriorityLimiter) currentNow() time.Time {
	d.localMu.Lock()
	fn := d.nowFn
	d.localMu.Unlock()
	if fn != nil {
		return fn().UTC()
	}
	return time.Now().UTC()
}

// SetPTUShareRepository attaches or replaces the PTUShareRepository.
func (d *DynamicPriorityLimiter) SetPTUShareRepository(repo storage.PTUShareRepository) {
	if d == nil {
		return
	}
	d.localMu.Lock()
	d.ptuRepo = repo
	d.localMu.Unlock()
}

func (d *DynamicPriorityLimiter) getPTURepo() storage.PTUShareRepository {
	if d == nil {
		return nil
	}
	d.localMu.Lock()
	repo := d.ptuRepo
	d.localMu.Unlock()
	return repo
}

// ResolveCallerID extracts a stable caller identifier (team preferred, then key)
// from an IdentityContext.
func ResolveCallerID(idCtx *domain.IdentityContext) string {
	if idCtx == nil {
		return ""
	}
	if id := strings.TrimSpace(idCtx.TeamID); id != "" {
		return "team:" + id
	}
	if id := strings.TrimSpace(idCtx.VirtualKeyID); id != "" {
		return "key:" + id
	}
	if id := strings.TrimSpace(idCtx.UserID); id != "" {
		return "user:" + id
	}
	return ""
}

// ResolvePriorityClassName maps an IdentityContext and optional request priority
// to a configured PriorityClass name when available.
func (d *DynamicPriorityLimiter) ResolvePriorityClassName(ctx context.Context, idCtx *domain.IdentityContext, req *domain.CanonicalChatRequest) (string, map[string]*domain.PriorityClass) {
	var orgID string
	if idCtx != nil {
		orgID = idCtx.OrgID
	}
	known := d.loadKnownClasses(ctx, orgID)

	if req != nil && req.GoRouteExtensions != nil {
		// Match explicit Priority rank against configured org priority classes.
		reqRank := req.GoRouteExtensions.Priority
		if len(known) > 0 {
			for _, pc := range known {
				if pc != nil && pc.PriorityRank == reqRank {
					return pc.Name, known
				}
			}
		}
		// Fallback to tag prefix "priority:<name>" if supplied.
		for _, tag := range req.GoRouteExtensions.Tags {
			trimmed := strings.TrimSpace(tag)
			if strings.HasPrefix(strings.ToLower(trimmed), "priority:") {
				name := strings.TrimSpace(trimmed[len("priority:"):])
				if name != "" {
					return name, known
				}
			}
		}
	}
	return defaultPriorityClassName, known
}

func (d *DynamicPriorityLimiter) loadKnownClasses(ctx context.Context, orgID string) map[string]*domain.PriorityClass {
	repo := d.getPTURepo()
	if repo == nil || strings.TrimSpace(orgID) == "" {
		return nil
	}
	list, err := repo.ListPriorityClasses(ctx, orgID)
	if err != nil || len(list) == 0 {
		return nil
	}
	out := make(map[string]*domain.PriorityClass, len(list))
	for _, pc := range list {
		if pc != nil {
			out[normalizeClassName(pc.Name)] = pc
		}
	}
	return out
}

// EvaluateAllowance computes the caller's Generous or Strict capacity allowance
// without incrementing usage counters.
func (d *DynamicPriorityLimiter) EvaluateAllowance(ctx context.Context, req PriorityCapacityRequest) (*PriorityAllowance, error) {
	if d == nil {
		return &PriorityAllowance{Allowed: true}, nil
	}
	total, byClass, err := d.registry.ActiveCounts(ctx, req.OrgID, req.Model)
	if err != nil {
		return nil, err
	}
	return d.computeAllowance(ctx, req, total, byClass), nil
}

// Admit registers the caller in ActiveTenantRegistry, computes Generous/Strict
// capacity allowances under real-time saturation, and atomically enforces the
// caller's per-window RPM/TPM allowance.
func (d *DynamicPriorityLimiter) Admit(ctx context.Context, req PriorityCapacityRequest) (*PriorityAllowance, error) {
	if d == nil {
		return &PriorityAllowance{Allowed: true}, nil
	}
	className := normalizeClassName(req.PriorityClass)
	callerID := normalizeCapKeySegment(req.CallerID)
	total, byClass, err := d.registry.Register(ctx, req.OrgID, req.Model, callerID, className)
	if err != nil {
		return nil, err
	}

	allowance := d.computeAllowance(ctx, req, total, byClass)

	// In Strict Mode, if a configured capacity dimension shares down to 0, reject immediately.
	if allowance.Mode == CapacityModeStrict {
		if req.CapRPM > 0 && allowance.EffectiveRPM <= 0 {
			return allowance, priorityCapacityExceededError("rpm", req.Model, allowance.Mode)
		}
		if req.CapTPM > 0 && (allowance.EffectiveTPM <= 0 || (req.EstimatedTokens > 0 && req.EstimatedTokens > allowance.EffectiveTPM)) {
			return allowance, priorityCapacityExceededError("tpm", req.Model, allowance.Mode)
		}
	}

	// If neither CapRPM nor CapTPM nor EffectiveRPM/TPM imposes a positive cap, admit.
	if allowance.EffectiveRPM <= 0 && allowance.EffectiveTPM <= 0 {
		allowance.Allowed = true
		return allowance, nil
	}

	now := d.currentNow()
	bucket := d.windowBucket(now)
	ttlSec := d.windowTTLSeconds()
	rpmKey := PriorityCallerRPMKey(req.OrgID, req.Model, callerID, bucket)
	tpmKey := PriorityCallerTPMKey(req.OrgID, req.Model, callerID, bucket)

	estTokens := req.EstimatedTokens
	if estTokens < 0 {
		estTokens = 0
	}

	allowed, dim, usedRPM, usedTPM := d.acquireRatePair(
		ctx,
		&d.localPriorityUsage,
		rpmKey, tpmKey,
		allowance.EffectiveRPM, allowance.EffectiveTPM,
		estTokens, bucket, ttlSec,
	)
	allowance.UsedCallerRPM = usedRPM
	allowance.UsedCallerTPM = usedTPM
	allowance.Allowed = allowed
	if !allowed {
		return allowance, priorityCapacityExceededError(dim, req.Model, allowance.Mode)
	}
	return allowance, nil
}

// ReconcileTokens adjusts the caller's TPM counter after upstream execution completes
// with actual token usage.
func (d *DynamicPriorityLimiter) ReconcileTokens(ctx context.Context, orgID, model, callerID string, estTokens, actualTokens int) {
	if d == nil {
		return
	}
	delta := actualTokens - estTokens
	if delta == 0 {
		return
	}
	now := d.currentNow()
	bucket := d.windowBucket(now)
	tpmKey := PriorityCallerTPMKey(orgID, model, normalizeCapKeySegment(callerID), bucket)
	d.reconcileRateKey(ctx, &d.localPriorityUsage, tpmKey, delta, bucket, d.windowTTLSeconds())
}

func (d *DynamicPriorityLimiter) computeAllowance(ctx context.Context, req PriorityCapacityRequest, activeTotal int, activeByClass map[string]int) *PriorityAllowance {
	className := normalizeClassName(req.PriorityClass)
	known := req.KnownClasses
	if len(known) == 0 && strings.TrimSpace(req.OrgID) != "" {
		known = d.loadKnownClasses(ctx, req.OrgID)
	}

	callerClass := d.lookupClassSpec(className, known)
	saturation := ComputeSaturation(req.UsedRPM, req.CapRPM, req.UsedTPM, req.CapTPM)

	// Include the caller's own class so active counts are always >= 1 for the requesting class.
	classCounts := make(map[string]int, len(activeByClass)+1)
	total := 0
	for c, n := range activeByClass {
		if n > 0 {
			nc := normalizeClassName(c)
			classCounts[nc] += n
			total += n
		}
	}
	if classCounts[className] <= 0 {
		classCounts[className] = 1
		total++
	}
	if activeTotal > total {
		total = activeTotal
	}
	inClass := classCounts[className]

	out := &PriorityAllowance{
		Saturation:           saturation,
		SaturationThreshold:  d.cfg.SaturationThreshold,
		PriorityClass:        className,
		ActiveCallersTotal:   total,
		ActiveCallersInClass: inClass,
		Allowed:              true,
	}

	if saturation < d.cfg.SaturationThreshold {
		// Generous Mode: allow borrowing unused capacity up to min(modelCapacity, baseLimit * maxBorrowMultiple).
		out.Mode = CapacityModeGenerous
		out.NormalizedWeight = 1.0
		borrow := callerClass.MaxBorrowMultiple
		if borrow <= 0 {
			borrow = d.cfg.DefaultBorrowMultiple
		}
		out.EffectiveRPM = generousEffectiveLimit(req.CapRPM, req.BaseRPM, borrow)
		out.EffectiveTPM = generousEffectiveLimit(req.CapTPM, req.BaseTPM, borrow)
		return out
	}

	// Strict Mode: normalize active priority class weights (w_c / sum(w_active_classes))
	// and divide each class's share fairly across active callers in that class.
	out.Mode = CapacityModeStrict
	var sumActiveWeights float64
	for activeCls, count := range classCounts {
		if count <= 0 {
			continue
		}
		spec := d.lookupClassSpec(activeCls, known)
		sumActiveWeights += spec.Weight
	}
	normWeight := 1.0
	if sumActiveWeights > 0 {
		normWeight = callerClass.Weight / sumActiveWeights
	}
	out.NormalizedWeight = normWeight

	if req.CapRPM > 0 {
		out.EffectiveRPM = int(math.Floor((float64(req.CapRPM) * normWeight) / float64(inClass)))
	}
	if req.CapTPM > 0 {
		out.EffectiveTPM = int(math.Floor((float64(req.CapTPM) * normWeight) / float64(inClass)))
	}
	return out
}

func (d *DynamicPriorityLimiter) lookupClassSpec(name string, known map[string]*domain.PriorityClass) domain.PriorityClass {
	name = normalizeClassName(name)
	if known != nil {
		if pc, ok := known[name]; ok && pc != nil {
			cp := *pc
			if cp.Weight <= 0 {
				cp.Weight = d.cfg.DefaultWeight
			}
			if cp.MaxBorrowMultiple <= 0 {
				cp.MaxBorrowMultiple = d.cfg.DefaultBorrowMultiple
			}
			return cp
		}
	}
	return domain.PriorityClass{
		Name:              name,
		Weight:            d.cfg.DefaultWeight,
		MaxBorrowMultiple: d.cfg.DefaultBorrowMultiple,
	}
}

func generousEffectiveLimit(modelCap, baseLimit int, borrowMultiple float64) int {
	if modelCap <= 0 && baseLimit <= 0 {
		return 0
	}
	if baseLimit <= 0 {
		return modelCap
	}
	borrowed := int(math.Floor(float64(baseLimit) * borrowMultiple))
	if modelCap > 0 && borrowed > modelCap {
		return modelCap
	}
	return borrowed
}

// EvaluateDeploymentPTU inspects deployment_ptu_shares for dep and computes how
// much capacity is reserved for other teams versus available for teamID.
func (d *DynamicPriorityLimiter) EvaluateDeploymentPTU(ctx context.Context, dep *domain.Deployment, teamID string) (PTUDeploymentAllocation, error) {
	var alloc PTUDeploymentAllocation
	if dep == nil {
		return alloc, nil
	}
	alloc.DeploymentID = dep.ID
	if dep.RPMCapacity > 0 {
		alloc.AvailableRPMForTeam = dep.RPMCapacity
	}
	if dep.TPMCapacity > 0 {
		alloc.AvailableTPMForTeam = dep.TPMCapacity
	}

	repo := d.getPTURepo()
	if repo == nil || strings.TrimSpace(dep.ID) == "" {
		return alloc, nil
	}
	shares, err := repo.ListDeploymentPTUShares(ctx, dep.ID)
	if err != nil || len(shares) == 0 {
		return alloc, err
	}

	alloc.HasAnyShares = true
	teamID = strings.TrimSpace(teamID)
	for _, s := range shares {
		if s == nil {
			continue
		}
		alloc.TotalReservedRPM += s.ReservedRPM
		alloc.TotalReservedTPM += s.ReservedTPM
		if teamID != "" && s.TeamID == teamID {
			alloc.TeamShare = s.Clone()
		} else {
			alloc.OtherTeamsReservedRPM += s.ReservedRPM
			alloc.OtherTeamsReservedTPM += s.ReservedTPM
		}
	}

	if dep.RPMCapacity > 0 {
		rem := dep.RPMCapacity - alloc.OtherTeamsReservedRPM
		if rem < 0 {
			rem = 0
		}
		alloc.AvailableRPMForTeam = rem
	}
	if dep.TPMCapacity > 0 {
		rem := dep.TPMCapacity - alloc.OtherTeamsReservedTPM
		if rem < 0 {
			rem = 0
		}
		alloc.AvailableTPMForTeam = rem
	}
	return alloc, nil
}

// AcquirePTUShare enforces a team's dedicated PTU RPM/TPM slice on depID using
// Redis counters (`gw:ptu:{org:<orgID>}:dep:<depID>:team:<teamID>:...`) and
// in-memory fallback. If the team has no PTU share on depID, Allowed=true and HasShare=false.
func (d *DynamicPriorityLimiter) AcquirePTUShare(ctx context.Context, orgID, depID, teamID string, estTokens int) (*PTUShareCheckResult, error) {
	if d == nil {
		return &PTUShareCheckResult{Allowed: true}, nil
	}
	repo := d.getPTURepo()
	teamID = strings.TrimSpace(teamID)
	depID = strings.TrimSpace(depID)
	if repo == nil || teamID == "" || depID == "" {
		return &PTUShareCheckResult{Allowed: true}, nil
	}

	shares, err := repo.ListDeploymentPTUShares(ctx, depID)
	if err != nil {
		return nil, err
	}
	var teamShare *domain.DeploymentPTUShare
	for _, s := range shares {
		if s != nil && s.TeamID == teamID {
			teamShare = s
			break
		}
	}
	if teamShare == nil {
		return &PTUShareCheckResult{HasShare: false, Allowed: true}, nil
	}

	if orgID == "" {
		orgID = teamShare.OrgID
	}
	res := &PTUShareCheckResult{
		HasShare:    true,
		ReservedRPM: teamShare.ReservedRPM,
		ReservedTPM: teamShare.ReservedTPM,
	}
	if teamShare.ReservedRPM <= 0 && teamShare.ReservedTPM <= 0 {
		res.Allowed = true
		return res, nil
	}

	if estTokens < 0 {
		estTokens = 0
	}
	now := d.currentNow()
	bucket := d.windowBucket(now)
	ttlSec := d.windowTTLSeconds()
	rpmKey := PTUTeamRPMKey(orgID, depID, teamID, bucket)
	tpmKey := PTUTeamTPMKey(orgID, depID, teamID, bucket)

	allowed, dim, usedRPM, usedTPM := d.acquireRatePair(
		ctx,
		&d.localPTUUsage,
		rpmKey, tpmKey,
		teamShare.ReservedRPM, teamShare.ReservedTPM,
		estTokens, bucket, ttlSec,
	)
	res.Allowed = allowed
	res.UsedRPM = usedRPM
	res.UsedTPM = usedTPM
	if !allowed {
		return res, &domain.GatewayError{
			StatusCode:    http.StatusTooManyRequests,
			Type:          domain.ErrorTypeRateLimit,
			Code:          "ptu_share_exceeded",
			Message:       fmt.Sprintf("Deployment %s PTU %s share exceeded for team %s", depID, dim, teamID),
			RetryAfterSec: d.retryAfterSeconds(now),
			Retryable:     true,
		}
	}
	return res, nil
}

// ReconcilePTUShare adjusts the team's PTU TPM counter by (actualTokens - estTokens).
func (d *DynamicPriorityLimiter) ReconcilePTUShare(ctx context.Context, orgID, depID, teamID string, estTokens, actualTokens int) {
	if d == nil {
		return
	}
	teamID = strings.TrimSpace(teamID)
	depID = strings.TrimSpace(depID)
	if teamID == "" || depID == "" {
		return
	}
	delta := actualTokens - estTokens
	if delta == 0 {
		return
	}
	now := d.currentNow()
	bucket := d.windowBucket(now)
	tpmKey := PTUTeamTPMKey(orgID, depID, teamID, bucket)
	d.reconcileRateKey(ctx, &d.localPTUUsage, tpmKey, delta, bucket, d.windowTTLSeconds())
}

func (d *DynamicPriorityLimiter) windowBucket(now time.Time) int64 {
	winSec := int64(d.cfg.WindowDuration.Seconds())
	if winSec <= 0 {
		winSec = 60
	}
	return now.Unix() / winSec
}

func (d *DynamicPriorityLimiter) windowTTLSeconds() int64 {
	winSec := int64(d.cfg.WindowDuration.Seconds())
	if winSec <= 0 {
		winSec = 60
	}
	return winSec * 2
}

func (d *DynamicPriorityLimiter) retryAfterSeconds(now time.Time) int {
	winSec := int64(d.cfg.WindowDuration.Seconds())
	if winSec <= 0 {
		winSec = 60
	}
	rem := int(winSec - (now.Unix() % winSec))
	if rem < 1 {
		rem = 1
	}
	return rem
}

func (d *DynamicPriorityLimiter) acquireRatePair(
	ctx context.Context,
	localStore *map[string]*localWindowCounter,
	rpmKey, tpmKey string,
	limitRPM, limitTPM, estTokens int,
	bucket, ttlSec int64,
) (allowed bool, exceededDim string, usedRPM, usedTPM int) {
	if d.redis != nil && d.redis.Client() != nil {
		if ctx == nil {
			ctx = context.Background()
		}
		rCtx, cancel := context.WithTimeout(ctx, d.cfg.RedisTimeout)
		defer cancel()

		res, err := d.redis.Execute(func(rdb redis.UniversalClient) (any, error) {
			return acquireWindowRateScript.Run(
				rCtx, rdb, []string{rpmKey, tpmKey},
				limitRPM, limitTPM, estTokens, ttlSec,
			).Result()
		})
		if err == nil {
			if ok, dim, rVal, tVal, parsed := parseAcquireRateScriptResult(res); parsed {
				return ok, dim, rVal, tVal
			}
		}
	}

	d.localMu.Lock()
	defer d.localMu.Unlock()
	if *localStore == nil {
		*localStore = make(map[string]*localWindowCounter)
	}
	baseKey := rpmKey
	c := (*localStore)[baseKey]
	if c == nil || c.bucket != bucket {
		c = &localWindowCounter{bucket: bucket}
		(*localStore)[baseKey] = c
	}
	if limitRPM > 0 && c.rpm+1 > limitRPM {
		return false, "rpm", c.rpm, c.tpm
	}
	if limitTPM > 0 && ((estTokens > 0 && c.tpm+estTokens > limitTPM) || (estTokens == 0 && c.tpm >= limitTPM)) {
		return false, "tpm", c.rpm, c.tpm
	}
	c.rpm++
	c.tpm += estTokens
	return true, "", c.rpm, c.tpm
}

func (d *DynamicPriorityLimiter) reconcileRateKey(
	ctx context.Context,
	localStore *map[string]*localWindowCounter,
	tpmKey string,
	delta int,
	bucket, ttlSec int64,
) {
	if d.redis != nil && d.redis.Client() != nil {
		if ctx == nil {
			ctx = context.Background()
		}
		rCtx, cancel := context.WithTimeout(ctx, d.cfg.RedisTimeout)
		defer cancel()

		if _, err := d.redis.Execute(func(rdb redis.UniversalClient) (any, error) {
			return reconcileWindowTokensScript.Run(rCtx, rdb, []string{tpmKey}, delta, ttlSec).Result()
		}); err == nil {
			return
		}
	}

	// Derive corresponding RPM key from ":tpm:" -> ":rpm:" for local fallback map.
	rpmKey := strings.Replace(tpmKey, ":tpm:", ":rpm:", 1)
	d.localMu.Lock()
	defer d.localMu.Unlock()
	if *localStore == nil {
		return
	}
	if c := (*localStore)[rpmKey]; c != nil && c.bucket == bucket {
		c.tpm += delta
		if c.tpm < 0 {
			c.tpm = 0
		}
	}
}

func parseAcquireRateScriptResult(res any) (allowed bool, dim string, usedRPM, usedTPM int, ok bool) {
	arr, isArr := res.([]any)
	if !isArr || len(arr) < 4 {
		return false, "", 0, 0, false
	}
	flag, ok1 := parseScriptInt(arr[0])
	rVal, ok2 := parseScriptInt(arr[2])
	tVal, ok3 := parseScriptInt(arr[3])
	if !ok1 || !ok2 || !ok3 {
		return false, "", 0, 0, false
	}
	dimStr, _ := arr[1].(string)
	return flag == 1, dimStr, rVal, tVal, true
}

func parseScriptInt(v any) (int, bool) {
	switch x := v.(type) {
	case int64:
		return int(x), true
	case int:
		return x, true
	case string:
		n, err := strconv.Atoi(x)
		return n, err == nil
	default:
		return 0, false
	}
}

func priorityCapacityExceededError(dim, model string, mode CapacityMode) *domain.GatewayError {
	return &domain.GatewayError{
		StatusCode: http.StatusTooManyRequests,
		Type:       domain.ErrorTypeRateLimit,
		Code:       "priority_capacity_exceeded",
		Message:    fmt.Sprintf("Dynamic priority %s capacity exceeded for model %s (mode=%s)", dim, model, mode),
		Retryable:  true,
	}
}

// --- Context helpers for passing caller team into deployment filtering ---

type callerTeamCtxKey struct{}

// WithCallerTeamID attaches teamID to ctx for PTU-aware deployment filtering.
func WithCallerTeamID(ctx context.Context, teamID string) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	if strings.TrimSpace(teamID) == "" {
		return ctx
	}
	return context.WithValue(ctx, callerTeamCtxKey{}, strings.TrimSpace(teamID))
}

// CallerTeamIDFromContext extracts the caller teamID attached by WithCallerTeamID.
func CallerTeamIDFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	if v, ok := ctx.Value(callerTeamCtxKey{}).(string); ok {
		return v
	}
	return ""
}
