package storage

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
	"weak"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// ToolTrustLevel classifies the trust boundary for a tool's inputs or outputs.
type ToolTrustLevel string

const (
	ToolTrustUntrusted ToolTrustLevel = "untrusted"
	ToolTrustTrusted   ToolTrustLevel = "trusted"
	ToolTrustBlocked   ToolTrustLevel = "blocked"
)

// IsValidInput reports whether l is a recognized input_policy value.
func (l ToolTrustLevel) IsValidInput() bool {
	switch l {
	case ToolTrustUntrusted, ToolTrustTrusted, ToolTrustBlocked:
		return true
	default:
		return false
	}
}

// IsValidOutput reports whether l is a recognized output_policy value.
func (l ToolTrustLevel) IsValidOutput() bool {
	switch l {
	case ToolTrustUntrusted, ToolTrustTrusted:
		return true
	default:
		return false
	}
}

// ToolPolicy defines tenant-scoped trust levels for a named tool's inputs and outputs.
type ToolPolicy struct {
	ID           string         `json:"id"`
	OrgID        string         `json:"org_id"`
	TeamID       string         `json:"team_id,omitempty"`
	VirtualKeyID string         `json:"virtual_key_id,omitempty"`
	ToolName     string         `json:"tool_name"`
	InputPolicy  ToolTrustLevel `json:"input_policy"`
	OutputPolicy ToolTrustLevel `json:"output_policy"`
	CreatedAt    time.Time      `json:"created_at"`
	UpdatedAt    time.Time      `json:"updated_at"`
}

// ToolPolicyFilter filters tool policy queries. Empty fields match all values except OrgID which is required for tenant scoping.
type ToolPolicyFilter struct {
	OrgID        string
	TeamID       string
	VirtualKeyID string
	ToolName     string
}

// ToolPolicyRepository defines persistence and scope-resolution operations for tool trust policies.
type ToolPolicyRepository interface {
	UpsertToolPolicy(ctx context.Context, policy *ToolPolicy) error
	GetToolPolicy(ctx context.Context, orgID, id string) (*ToolPolicy, error)
	ListToolPolicies(ctx context.Context, filter ToolPolicyFilter) ([]*ToolPolicy, error)
	DeleteToolPolicy(ctx context.Context, orgID, id string) error
	ResolveEffectiveToolPolicies(ctx context.Context, orgID, teamID, virtualKeyID string) (map[string]*ToolPolicy, error)
}

// MemoryStore and PostgresStore are compatibility aliases for MemoryRepository and PostgresRepository.
type (
	MemoryStore   = MemoryRepository
	PostgresStore = PostgresRepository
)

var (
	_ ToolPolicyRepository = (*MemoryRepository)(nil)
	_ ToolPolicyRepository = (*PostgresRepository)(nil)
)

type memoryToolPolicyEntry struct {
	repo     weak.Pointer[MemoryRepository]
	mu       sync.RWMutex
	policies map[string]*ToolPolicy
}

var memToolPolicyTables sync.Map // uintptr -> *memoryToolPolicyEntry

func getMemoryToolPolicyEntry(r *MemoryRepository) *memoryToolPolicyEntry {
	key := reflect.ValueOf(r).Pointer()
	if existing, ok := memToolPolicyTables.Load(key); ok {
		if entry, ok := existing.(*memoryToolPolicyEntry); ok && entry.repo.Value() == r {
			return entry
		}
	}
	entry := &memoryToolPolicyEntry{
		repo:     weak.Make(r),
		policies: make(map[string]*ToolPolicy),
	}
	actual, loaded := memToolPolicyTables.LoadOrStore(key, entry)
	if loaded {
		if existing, ok := actual.(*memoryToolPolicyEntry); ok && existing.repo.Value() == r {
			return existing
		}
		memToolPolicyTables.Store(key, entry)
	}
	runtime.AddCleanup(r, func(k uintptr) {
		if cur, ok := memToolPolicyTables.Load(k); ok {
			if ce, ok := cur.(*memoryToolPolicyEntry); ok && ce == entry {
				memToolPolicyTables.Delete(k)
			}
		}
	}, key)
	return entry
}

func cloneToolPolicy(p *ToolPolicy) *ToolPolicy {
	if p == nil {
		return nil
	}
	cp := *p
	return &cp
}

func normalizeToolPolicy(p *ToolPolicy) error {
	if p == nil {
		return fmt.Errorf("tool policy is required")
	}
	p.OrgID = strings.TrimSpace(p.OrgID)
	if p.OrgID == "" {
		return fmt.Errorf("org_id is required for tool policy")
	}
	p.TeamID = strings.TrimSpace(p.TeamID)
	p.VirtualKeyID = strings.TrimSpace(p.VirtualKeyID)
	p.ToolName = strings.TrimSpace(p.ToolName)
	if p.ToolName == "" {
		return fmt.Errorf("tool_name is required for tool policy")
	}
	p.InputPolicy = ToolTrustLevel(strings.ToLower(strings.TrimSpace(string(p.InputPolicy))))
	if p.InputPolicy == "" {
		p.InputPolicy = ToolTrustUntrusted
	}
	if !p.InputPolicy.IsValidInput() {
		return fmt.Errorf("invalid input_policy %q: must be untrusted, trusted, or blocked", p.InputPolicy)
	}
	p.OutputPolicy = ToolTrustLevel(strings.ToLower(strings.TrimSpace(string(p.OutputPolicy))))
	if p.OutputPolicy == "" {
		p.OutputPolicy = ToolTrustUntrusted
	}
	if !p.OutputPolicy.IsValidOutput() {
		return fmt.Errorf("invalid output_policy %q: must be untrusted or trusted", p.OutputPolicy)
	}
	return nil
}

func toolPolicyScopeSpecificity(p *ToolPolicy, teamID, virtualKeyID string) (int, bool) {
	if p == nil {
		return 0, false
	}
	if p.TeamID != "" && p.TeamID != teamID {
		return 0, false
	}
	if p.VirtualKeyID != "" && p.VirtualKeyID != virtualKeyID {
		return 0, false
	}
	score := 1
	if p.TeamID != "" && p.TeamID == teamID {
		score += 1
	}
	if p.VirtualKeyID != "" && p.VirtualKeyID == virtualKeyID {
		score += 2
	}
	return score, true
}

func sortToolPolicies(list []*ToolPolicy) {
	sort.Slice(list, func(i, j int) bool {
		if list[i].OrgID != list[j].OrgID {
			return list[i].OrgID < list[j].OrgID
		}
		if list[i].ToolName != list[j].ToolName {
			return list[i].ToolName < list[j].ToolName
		}
		if list[i].TeamID != list[j].TeamID {
			return list[i].TeamID < list[j].TeamID
		}
		if list[i].VirtualKeyID != list[j].VirtualKeyID {
			return list[i].VirtualKeyID < list[j].VirtualKeyID
		}
		return list[i].ID < list[j].ID
	})
}

func (r *MemoryRepository) UpsertToolPolicy(_ context.Context, policy *ToolPolicy) error {
	if r == nil {
		return fmt.Errorf("memory repository is nil")
	}
	if err := normalizeToolPolicy(policy); err != nil {
		return err
	}

	entry := getMemoryToolPolicyEntry(r)
	entry.mu.Lock()
	defer entry.mu.Unlock()

	now := time.Now().UTC()
	for id, existing := range entry.policies {
		if existing.OrgID == policy.OrgID &&
			existing.TeamID == policy.TeamID &&
			existing.VirtualKeyID == policy.VirtualKeyID &&
			existing.ToolName == policy.ToolName {
			policy.ID = id
			policy.CreatedAt = existing.CreatedAt
			policy.UpdatedAt = now
			entry.policies[id] = cloneToolPolicy(policy)
			return nil
		}
	}

	if policy.ID == "" {
		policy.ID = uuid.NewString()
	}
	if policy.CreatedAt.IsZero() {
		policy.CreatedAt = now
	}
	policy.UpdatedAt = now
	entry.policies[policy.ID] = cloneToolPolicy(policy)
	return nil
}

func (r *MemoryRepository) GetToolPolicy(_ context.Context, orgID, id string) (*ToolPolicy, error) {
	if r == nil {
		return nil, fmt.Errorf("memory repository is nil")
	}
	orgID = strings.TrimSpace(orgID)
	if orgID == "" {
		return nil, fmt.Errorf("org_id is required")
	}
	entry := getMemoryToolPolicyEntry(r)
	entry.mu.RLock()
	defer entry.mu.RUnlock()

	p, ok := entry.policies[id]
	if !ok || p.OrgID != orgID {
		return nil, fmt.Errorf("tool policy %q %w", id, ErrNotFound)
	}
	return cloneToolPolicy(p), nil
}

func (r *MemoryRepository) ListToolPolicies(_ context.Context, filter ToolPolicyFilter) ([]*ToolPolicy, error) {
	if r == nil {
		return nil, fmt.Errorf("memory repository is nil")
	}
	orgID := strings.TrimSpace(filter.OrgID)
	if orgID == "" {
		return nil, fmt.Errorf("org_id is required")
	}
	teamID := strings.TrimSpace(filter.TeamID)
	vkID := strings.TrimSpace(filter.VirtualKeyID)
	toolName := strings.TrimSpace(filter.ToolName)

	entry := getMemoryToolPolicyEntry(r)
	entry.mu.RLock()
	defer entry.mu.RUnlock()

	var out []*ToolPolicy
	for _, p := range entry.policies {
		if p.OrgID != orgID {
			continue
		}
		if teamID != "" && p.TeamID != teamID {
			continue
		}
		if vkID != "" && p.VirtualKeyID != vkID {
			continue
		}
		if toolName != "" && p.ToolName != toolName {
			continue
		}
		out = append(out, cloneToolPolicy(p))
	}
	sortToolPolicies(out)
	return out, nil
}

func (r *MemoryRepository) DeleteToolPolicy(_ context.Context, orgID, id string) error {
	if r == nil {
		return fmt.Errorf("memory repository is nil")
	}
	orgID = strings.TrimSpace(orgID)
	if orgID == "" {
		return fmt.Errorf("org_id is required")
	}
	entry := getMemoryToolPolicyEntry(r)
	entry.mu.Lock()
	defer entry.mu.Unlock()

	p, ok := entry.policies[id]
	if !ok || p.OrgID != orgID {
		return fmt.Errorf("tool policy %q %w", id, ErrNotFound)
	}
	delete(entry.policies, id)
	return nil
}

func (r *MemoryRepository) ResolveEffectiveToolPolicies(_ context.Context, orgID, teamID, virtualKeyID string) (map[string]*ToolPolicy, error) {
	if r == nil {
		return nil, fmt.Errorf("memory repository is nil")
	}
	orgID = strings.TrimSpace(orgID)
	if orgID == "" {
		return map[string]*ToolPolicy{}, nil
	}
	teamID = strings.TrimSpace(teamID)
	virtualKeyID = strings.TrimSpace(virtualKeyID)

	entry := getMemoryToolPolicyEntry(r)
	entry.mu.RLock()
	defer entry.mu.RUnlock()

	type scoredPolicy struct {
		score  int
		policy *ToolPolicy
	}
	best := make(map[string]scoredPolicy)
	for _, p := range entry.policies {
		if p.OrgID != orgID {
			continue
		}
		score, ok := toolPolicyScopeSpecificity(p, teamID, virtualKeyID)
		if !ok {
			continue
		}
		cur, exists := best[p.ToolName]
		if !exists || score > cur.score || (score == cur.score && p.ID > cur.policy.ID) {
			best[p.ToolName] = scoredPolicy{score: score, policy: p}
		}
	}

	resolved := make(map[string]*ToolPolicy, len(best))
	for name, sp := range best {
		resolved[name] = cloneToolPolicy(sp.policy)
	}
	return resolved, nil
}

const toolPolicySelectCols = `
	id, org_id, COALESCE(team_id, ''), COALESCE(virtual_key_id, ''),
	tool_name, input_policy, output_policy, created_at, updated_at`

func scanToolPolicy(row pgx.Row) (*ToolPolicy, error) {
	var p ToolPolicy
	var inPol, outPol string
	if err := row.Scan(
		&p.ID, &p.OrgID, &p.TeamID, &p.VirtualKeyID,
		&p.ToolName, &inPol, &outPol, &p.CreatedAt, &p.UpdatedAt,
	); err != nil {
		return nil, err
	}
	p.InputPolicy = ToolTrustLevel(inPol)
	p.OutputPolicy = ToolTrustLevel(outPol)
	return &p, nil
}

func (p *PostgresRepository) syncToolPolicyMem(tp *ToolPolicy) {
	if p == nil || p.mem == nil || tp == nil {
		return
	}
	entry := getMemoryToolPolicyEntry(p.mem)
	entry.mu.Lock()
	entry.policies[tp.ID] = cloneToolPolicy(tp)
	entry.mu.Unlock()
}

func (p *PostgresRepository) UpsertToolPolicy(ctx context.Context, policy *ToolPolicy) error {
	if p == nil {
		return fmt.Errorf("postgres repository is nil")
	}
	if p.pool == nil {
		return p.mem.UpsertToolPolicy(ctx, policy)
	}
	if err := normalizeToolPolicy(policy); err != nil {
		return err
	}
	if policy.ID == "" {
		policy.ID = uuid.NewString()
	}

	const q = `
		INSERT INTO tool_policies (
			id, org_id, team_id, virtual_key_id, tool_name, input_policy, output_policy
		) VALUES (
			$1, $2, NULLIF($3, ''), NULLIF($4, ''), $5, $6, $7
		)
		ON CONFLICT (org_id, team_id, virtual_key_id, tool_name) DO UPDATE SET
			input_policy = EXCLUDED.input_policy,
			output_policy = EXCLUDED.output_policy,
			updated_at = NOW()
		RETURNING id, created_at, updated_at`

	if err := p.pool.QueryRow(ctx, q,
		policy.ID,
		policy.OrgID,
		policy.TeamID,
		policy.VirtualKeyID,
		policy.ToolName,
		string(policy.InputPolicy),
		string(policy.OutputPolicy),
	).Scan(&policy.ID, &policy.CreatedAt, &policy.UpdatedAt); err != nil {
		return err
	}
	p.syncToolPolicyMem(policy)
	return nil
}

func (p *PostgresRepository) GetToolPolicy(ctx context.Context, orgID, id string) (*ToolPolicy, error) {
	if p == nil {
		return nil, fmt.Errorf("postgres repository is nil")
	}
	if p.pool == nil {
		return p.mem.GetToolPolicy(ctx, orgID, id)
	}
	orgID = strings.TrimSpace(orgID)
	if orgID == "" {
		return nil, fmt.Errorf("org_id is required")
	}
	const q = `SELECT ` + toolPolicySelectCols + ` FROM tool_policies WHERE id = $1 AND org_id = $2`
	tp, err := scanToolPolicy(p.pool.QueryRow(ctx, q, id, orgID))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("tool policy %q %w", id, ErrNotFound)
		}
		return nil, err
	}
	p.syncToolPolicyMem(tp)
	return tp, nil
}

func (p *PostgresRepository) ListToolPolicies(ctx context.Context, filter ToolPolicyFilter) ([]*ToolPolicy, error) {
	if p == nil {
		return nil, fmt.Errorf("postgres repository is nil")
	}
	if p.pool == nil {
		return p.mem.ListToolPolicies(ctx, filter)
	}
	orgID := strings.TrimSpace(filter.OrgID)
	if orgID == "" {
		return nil, fmt.Errorf("org_id is required")
	}
	const q = `
		SELECT ` + toolPolicySelectCols + `
		FROM tool_policies
		WHERE org_id = $1
		  AND ($2 = '' OR team_id = $2)
		  AND ($3 = '' OR virtual_key_id = $3)
		  AND ($4 = '' OR tool_name = $4)
		ORDER BY tool_name ASC, team_id ASC NULLS FIRST, virtual_key_id ASC NULLS FIRST, id ASC`

	rows, err := p.pool.Query(ctx, q,
		orgID,
		strings.TrimSpace(filter.TeamID),
		strings.TrimSpace(filter.VirtualKeyID),
		strings.TrimSpace(filter.ToolName),
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*ToolPolicy
	for rows.Next() {
		tp, err := scanToolPolicy(rows)
		if err != nil {
			return nil, err
		}
		p.syncToolPolicyMem(tp)
		out = append(out, tp)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (p *PostgresRepository) DeleteToolPolicy(ctx context.Context, orgID, id string) error {
	if p == nil {
		return fmt.Errorf("postgres repository is nil")
	}
	if p.pool == nil {
		return p.mem.DeleteToolPolicy(ctx, orgID, id)
	}
	orgID = strings.TrimSpace(orgID)
	if orgID == "" {
		return fmt.Errorf("org_id is required")
	}
	tag, err := p.pool.Exec(ctx, `DELETE FROM tool_policies WHERE id = $1 AND org_id = $2`, id, orgID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("tool policy %q %w", id, ErrNotFound)
	}
	if p.mem != nil {
		_ = p.mem.DeleteToolPolicy(ctx, orgID, id)
	}
	return nil
}

func (p *PostgresRepository) ResolveEffectiveToolPolicies(ctx context.Context, orgID, teamID, virtualKeyID string) (map[string]*ToolPolicy, error) {
	if p == nil {
		return nil, fmt.Errorf("postgres repository is nil")
	}
	if p.pool == nil {
		return p.mem.ResolveEffectiveToolPolicies(ctx, orgID, teamID, virtualKeyID)
	}
	orgID = strings.TrimSpace(orgID)
	if orgID == "" {
		return map[string]*ToolPolicy{}, nil
	}
	teamID = strings.TrimSpace(teamID)
	virtualKeyID = strings.TrimSpace(virtualKeyID)

	const q = `
		SELECT ` + toolPolicySelectCols + `
		FROM tool_policies
		WHERE org_id = $1
		  AND (team_id IS NULL OR team_id = $2)
		  AND (virtual_key_id IS NULL OR virtual_key_id = $3)
		ORDER BY
			CASE WHEN team_id IS NOT NULL THEN 1 ELSE 0 END +
			CASE WHEN virtual_key_id IS NOT NULL THEN 2 ELSE 0 END ASC,
			id ASC`

	rows, err := p.pool.Query(ctx, q, orgID, teamID, virtualKeyID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	resolved := make(map[string]*ToolPolicy)
	for rows.Next() {
		tp, err := scanToolPolicy(rows)
		if err != nil {
			return nil, err
		}
		p.syncToolPolicyMem(tp)
		resolved[tp.ToolName] = tp
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return resolved, nil
}
