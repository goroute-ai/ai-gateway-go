package storage

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
)

func (r *MemoryRepository) CreateOrganization(ctx context.Context, org *domain.Organization) error {
	if org.SelfServeBudgetPolicy == "" {
		org.SelfServeBudgetPolicy = domain.SelfServeBudgetDisabled
	} else {
		p := domain.SelfServeBudgetPolicy(strings.ToLower(strings.TrimSpace(string(org.SelfServeBudgetPolicy))))
		if !p.IsValid() {
			return fmt.Errorf("invalid self_serve_budget_policy %q", org.SelfServeBudgetPolicy)
		}
		org.SelfServeBudgetPolicy = p
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if org.ID == "" {
		org.ID = uuid.NewString()
	}
	now := time.Now().UTC()
	org.BudgetResetPeriod, org.BudgetResetAt = resolveBudgetResetSchedule(org.BudgetResetPeriod, org.BudgetResetAt, now)
	org.CreatedAt = now
	org.UpdatedAt = now
	r.orgs[org.ID] = cloneOrganization(org)
	return nil
}

func (r *MemoryRepository) GetOrganization(ctx context.Context, id string) (*domain.Organization, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	org, ok := r.orgs[id]
	if !ok {
		return nil, fmt.Errorf("organization %q not found", id)
	}
	return cloneOrganization(org), nil
}

func (r *MemoryRepository) ListOrganizations(ctx context.Context) ([]*domain.Organization, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*domain.Organization, 0, len(r.orgs))
	for _, o := range r.orgs {
		out = append(out, cloneOrganization(o))
	}
	return out, nil
}

func (r *MemoryRepository) UpdateOrganization(ctx context.Context, org *domain.Organization) error {
	if org == nil || org.ID == "" {
		return fmt.Errorf("organization id is required")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	existing, ok := r.orgs[org.ID]
	if !ok {
		return fmt.Errorf("organization %q %w", org.ID, ErrNotFound)
	}
	if org.SelfServeBudgetPolicy == "" {
		org.SelfServeBudgetPolicy = existing.SelfServeBudgetPolicy
		if org.SelfServeBudgetPolicy == "" {
			org.SelfServeBudgetPolicy = domain.SelfServeBudgetDisabled
		}
	} else {
		p := domain.SelfServeBudgetPolicy(strings.ToLower(strings.TrimSpace(string(org.SelfServeBudgetPolicy))))
		if !p.IsValid() {
			return fmt.Errorf("invalid self_serve_budget_policy %q", org.SelfServeBudgetPolicy)
		}
		org.SelfServeBudgetPolicy = p
	}
	now := time.Now().UTC()
	if org.CreatedAt.IsZero() {
		org.CreatedAt = existing.CreatedAt
	}
	org.BudgetResetPeriod, org.BudgetResetAt = resolveBudgetResetSchedule(org.BudgetResetPeriod, org.BudgetResetAt, now)
	org.UpdatedAt = now
	r.orgs[org.ID] = cloneOrganization(org)
	return nil
}

func (r *MemoryRepository) SetOrgProviderSubscription(ctx context.Context, sub *domain.OrgProviderSubscription) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.orgSubs[sub.OrgID] == nil {
		r.orgSubs[sub.OrgID] = make(map[domain.ProviderType]*domain.OrgProviderSubscription)
	}
	if sub.SubscribedAt.IsZero() {
		sub.SubscribedAt = time.Now().UTC()
	}
	cp := *sub
	r.orgSubs[sub.OrgID][sub.Provider] = &cp
	r.routingRev.Add(1)
	return nil
}

func (r *MemoryRepository) GetOrgProviderSubscriptions(ctx context.Context, orgID string) ([]*domain.OrgProviderSubscription, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	subs := r.orgSubs[orgID]
	out := make([]*domain.OrgProviderSubscription, 0, len(subs))
	for _, s := range subs {
		cp := *s
		out = append(out, &cp)
	}
	return out, nil
}

func (r *MemoryRepository) SetOrgModelPolicy(ctx context.Context, pol *domain.OrgModelPolicy) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.orgPolicies[pol.OrgID] == nil {
		r.orgPolicies[pol.OrgID] = make(map[string]*domain.OrgModelPolicy)
	}
	if pol.ApprovedAt.IsZero() {
		pol.ApprovedAt = time.Now().UTC()
	}
	cp := *pol
	r.orgPolicies[pol.OrgID][pol.GlobalModelID] = &cp
	r.routingRev.Add(1)
	return nil
}

func (r *MemoryRepository) GetOrgModelPolicies(ctx context.Context, orgID string) ([]*domain.OrgModelPolicy, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	pols := r.orgPolicies[orgID]
	out := make([]*domain.OrgModelPolicy, 0, len(pols))
	for _, p := range pols {
		cp := *p
		out = append(out, &cp)
	}
	return out, nil
}

func cloneTeam(team *domain.Team) *domain.Team {
	if team == nil {
		return nil
	}
	cp := *team
	cp.MaxConcurrentRequests = team.MaxConcurrentRequests
	cp.BudgetFallbacks = domain.CloneBudgetFallbacks(team.BudgetFallbacks)
	cp.BudgetResetAt = cloneTimePtr(team.BudgetResetAt)
	cp.TempBudgetExpiresAt = cloneTimePtr(team.TempBudgetExpiresAt)
	cp.AllowedModels = slices.Clone(team.AllowedModels)
	cp.AllowedMCPServers = slices.Clone(team.AllowedMCPServers)
	cp.AllowedA2AAgents = slices.Clone(team.AllowedA2AAgents)
	cp.AllowedClientApps = slices.Clone(team.AllowedClientApps)
	cp.DefaultMemberAllowedModels = slices.Clone(team.DefaultMemberAllowedModels)
	cp.TeamMemberPermissions = slices.Clone(team.TeamMemberPermissions)
	cp.AllowedRoutingTags = slices.Clone(team.AllowedRoutingTags)
	return &cp
}

func (r *MemoryRepository) CreateTeam(ctx context.Context, team *domain.Team) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if team.ID == "" {
		team.ID = uuid.NewString()
	}
	now := time.Now().UTC()
	team.BudgetResetPeriod, team.BudgetResetAt = resolveBudgetResetSchedule(team.BudgetResetPeriod, team.BudgetResetAt, now)
	team.CreatedAt = now
	team.UpdatedAt = now
	cp := cloneTeam(team)
	r.teams[cp.ID] = cp
	return nil
}

func (r *MemoryRepository) UpdateTeam(ctx context.Context, team *domain.Team) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if team == nil || team.ID == "" {
		return fmt.Errorf("team id is required")
	}
	existing, ok := r.teams[team.ID]
	if !ok {
		return fmt.Errorf("team %q %w", team.ID, ErrNotFound)
	}
	now := time.Now().UTC()
	if team.OrgID == "" {
		team.OrgID = existing.OrgID
	}
	if team.CreatedAt.IsZero() {
		team.CreatedAt = existing.CreatedAt
	}
	team.BudgetResetPeriod, team.BudgetResetAt = resolveBudgetResetSchedule(team.BudgetResetPeriod, team.BudgetResetAt, now)
	team.UpdatedAt = now
	cp := cloneTeam(team)
	r.teams[cp.ID] = cp
	return nil
}

func (r *MemoryRepository) GetTeam(ctx context.Context, id string) (*domain.Team, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	t, ok := r.teams[id]
	if !ok {
		return nil, fmt.Errorf("team %q %w", id, ErrNotFound)
	}
	return cloneTeam(t), nil
}

func (r *MemoryRepository) GetTeamByName(ctx context.Context, orgID, name string) (*domain.Team, error) {
	orgID = strings.TrimSpace(orgID)
	name = strings.TrimSpace(name)
	if orgID == "" || name == "" {
		return nil, fmt.Errorf("team with org_id %q and name %q %w", orgID, name, ErrNotFound)
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, t := range r.teams {
		if t.OrgID == orgID && t.Name == name {
			return cloneTeam(t), nil
		}
	}
	return nil, fmt.Errorf("team with org_id %q and name %q %w", orgID, name, ErrNotFound)
}

func (r *MemoryRepository) ListTeams(ctx context.Context, orgID string) ([]*domain.Team, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []*domain.Team
	for _, t := range r.teams {
		if orgID == "" || t.OrgID == orgID {
			out = append(out, cloneTeam(t))
		}
	}
	return out, nil
}

func (r *MemoryRepository) DeleteTeam(ctx context.Context, id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.teams[id]; !ok {
		return fmt.Errorf("team %q %w", id, ErrNotFound)
	}
	for _, share := range r.ptuShares {
		if share != nil && share.TeamID == id {
			return fmt.Errorf("team %q cannot be deleted while it holds active PTU shares: %w", id, ErrTeamHasActivePTUShares)
		}
	}
	delete(r.teams, id)
	for mID, m := range r.teamMemberships {
		if m.TeamID == id {
			delete(r.teamMembershipsByTuple, teamMembershipTupleKey(m.TeamID, m.UserID))
			delete(r.teamMemberships, mID)
		}
	}
	for pID, p := range r.projects {
		if p.TeamID == id {
			delete(r.projectsByTeamName, projectNameTupleKey(p.TeamID, p.Name))
			delete(r.projects, pID)
			for _, vk := range r.keysByID {
				if vk.ProjectID == pID {
					vk.ProjectID = ""
				}
			}
		}
	}
	return nil
}

func cloneUser(user *domain.User) *domain.User {
	if user == nil {
		return nil
	}
	cp := *user
	cp.BudgetFallbacks = domain.CloneBudgetFallbacks(user.BudgetFallbacks)
	cp.BudgetResetAt = cloneTimePtr(user.BudgetResetAt)
	cp.TempBudgetExpiresAt = cloneTimePtr(user.TempBudgetExpiresAt)
	return &cp
}

func (r *MemoryRepository) CreateUser(ctx context.Context, user *domain.User) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if user.ID == "" {
		user.ID = uuid.NewString()
	}
	if user.IsActive && strings.TrimSpace(user.SCIMExternalID) == "" {
		user.SCIMActive = true
	}
	now := time.Now().UTC()
	user.BudgetResetPeriod, user.BudgetResetAt = resolveBudgetResetSchedule(user.BudgetResetPeriod, user.BudgetResetAt, now)
	user.CreatedAt = now
	user.UpdatedAt = now
	cp := cloneUser(user)
	r.users[cp.ID] = cp
	return nil
}

func (r *MemoryRepository) UpdateUser(ctx context.Context, user *domain.User) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if user == nil || user.ID == "" {
		return fmt.Errorf("user id is required")
	}
	existing, ok := r.users[user.ID]
	if !ok {
		return fmt.Errorf("user %q %w", user.ID, ErrNotFound)
	}
	now := time.Now().UTC()
	if user.OrgID == "" {
		user.OrgID = existing.OrgID
	}
	if user.CreatedAt.IsZero() {
		user.CreatedAt = existing.CreatedAt
	}
	user.BudgetResetPeriod, user.BudgetResetAt = resolveBudgetResetSchedule(user.BudgetResetPeriod, user.BudgetResetAt, now)
	user.UpdatedAt = now
	cp := cloneUser(user)
	r.users[cp.ID] = cp
	return nil
}

func (r *MemoryRepository) GetUser(ctx context.Context, id string) (*domain.User, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	u, ok := r.users[id]
	if !ok {
		return nil, fmt.Errorf("user %q %w", id, ErrNotFound)
	}
	return cloneUser(u), nil
}

func (r *MemoryRepository) GetUserByOIDCSubject(ctx context.Context, subject string) (*domain.User, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, u := range r.users {
		if u.OIDCSubject != "" && u.OIDCSubject == subject {
			return cloneUser(u), nil
		}
	}
	return nil, fmt.Errorf("user with oidc_subject %q not found", subject)
}

func (r *MemoryRepository) ListUsers(ctx context.Context, orgID string) ([]*domain.User, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []*domain.User
	for _, u := range r.users {
		if orgID == "" || u.OrgID == orgID {
			out = append(out, cloneUser(u))
		}
	}
	return out, nil
}

func (r *MemoryRepository) DeleteUser(ctx context.Context, id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.users[id]; !ok {
		return fmt.Errorf("user %q %w", id, ErrNotFound)
	}
	delete(r.users, id)
	for mID, m := range r.teamMemberships {
		if m.UserID == id {
			delete(r.teamMembershipsByTuple, teamMembershipTupleKey(m.TeamID, m.UserID))
			delete(r.teamMemberships, mID)
		}
	}
	delete(r.userCredentials, id)
	for sessID, sess := range r.operatorSessions {
		if sess != nil && sess.UserID == id {
			delete(r.operatorSessions, sessID)
		}
	}
	return nil
}

func (r *MemoryRepository) UpsertTeamMembership(_ context.Context, m *domain.TeamMembership) error {
	if err := normalizeTeamMembership(m); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now().UTC()
	tupleKey := teamMembershipTupleKey(m.TeamID, m.UserID)
	if existingID, ok := r.teamMembershipsByTuple[tupleKey]; ok {
		existing := r.teamMemberships[existingID]
		m.ID = existing.ID
		m.CreatedAt = existing.CreatedAt
		if existing.SpentMicros > m.SpentMicros {
			m.SpentMicros = existing.SpentMicros
		}
		m.UpdatedAt = now
		r.teamMemberships[existing.ID] = cloneTeamMembership(m)
		return nil
	}

	if m.ID == "" {
		m.ID = uuid.NewString()
	} else if _, exists := r.teamMemberships[m.ID]; exists {
		return fmt.Errorf("team membership %q already exists: %w", m.ID, ErrConflict)
	}
	if m.CreatedAt.IsZero() {
		m.CreatedAt = now
	}
	m.UpdatedAt = now
	r.teamMemberships[m.ID] = cloneTeamMembership(m)
	r.teamMembershipsByTuple[tupleKey] = m.ID
	return nil
}

func (r *MemoryRepository) GetTeamMembership(_ context.Context, teamID, userID string) (*domain.TeamMembership, error) {
	teamID = strings.TrimSpace(teamID)
	userID = strings.TrimSpace(userID)
	r.mu.RLock()
	defer r.mu.RUnlock()
	id, ok := r.teamMembershipsByTuple[teamMembershipTupleKey(teamID, userID)]
	if !ok {
		return nil, fmt.Errorf("team membership (%q, %q) %w", teamID, userID, ErrNotFound)
	}
	m, ok := r.teamMemberships[id]
	if !ok {
		return nil, fmt.Errorf("team membership (%q, %q) %w", teamID, userID, ErrNotFound)
	}
	return cloneTeamMembership(m), nil
}

func (r *MemoryRepository) ListTeamMemberships(_ context.Context, orgID, teamID, userID string) ([]*domain.TeamMembership, error) {
	orgID = strings.TrimSpace(orgID)
	teamID = strings.TrimSpace(teamID)
	userID = strings.TrimSpace(userID)
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []*domain.TeamMembership
	for _, m := range r.teamMemberships {
		if orgID != "" && m.OrgID != orgID {
			continue
		}
		if teamID != "" && m.TeamID != teamID {
			continue
		}
		if userID != "" && m.UserID != userID {
			continue
		}
		out = append(out, cloneTeamMembership(m))
	}
	sortTeamMemberships(out)
	return out, nil
}

func (r *MemoryRepository) DeleteTeamMembership(_ context.Context, teamID, userID string) error {
	teamID = strings.TrimSpace(teamID)
	userID = strings.TrimSpace(userID)
	r.mu.Lock()
	defer r.mu.Unlock()
	tupleKey := teamMembershipTupleKey(teamID, userID)
	id, ok := r.teamMembershipsByTuple[tupleKey]
	if !ok {
		return fmt.Errorf("team membership (%q, %q) %w", teamID, userID, ErrNotFound)
	}
	delete(r.teamMembershipsByTuple, tupleKey)
	delete(r.teamMemberships, id)
	return nil
}

func (r *MemoryRepository) BulkSyncTeamMemberships(_ context.Context, orgID, teamID string, upserts []*domain.TeamMembership, removeUserIDs []string) ([]*domain.TeamMembership, int, error) {
	orgID = strings.TrimSpace(orgID)
	teamID = strings.TrimSpace(teamID)
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now().UTC()
	var results []*domain.TeamMembership
	for _, entry := range upserts {
		if entry == nil {
			continue
		}
		m := cloneTeamMembership(entry)
		m.OrgID = orgID
		m.TeamID = teamID
		if err := normalizeTeamMembership(m); err != nil {
			return nil, 0, err
		}
		tupleKey := teamMembershipTupleKey(m.TeamID, m.UserID)
		if existingID, ok := r.teamMembershipsByTuple[tupleKey]; ok {
			existing := r.teamMemberships[existingID]
			m.ID = existing.ID
			m.CreatedAt = existing.CreatedAt
			if existing.SpentMicros > m.SpentMicros {
				m.SpentMicros = existing.SpentMicros
			}
			m.UpdatedAt = now
		} else {
			if m.ID == "" {
				m.ID = uuid.NewString()
			}
			if m.CreatedAt.IsZero() {
				m.CreatedAt = now
			}
			m.UpdatedAt = now
			r.teamMembershipsByTuple[tupleKey] = m.ID
		}
		stored := cloneTeamMembership(m)
		r.teamMemberships[stored.ID] = stored
		results = append(results, cloneTeamMembership(stored))
	}

	var removed int
	for _, rawUID := range removeUserIDs {
		uid := strings.TrimSpace(rawUID)
		if uid == "" {
			continue
		}
		tupleKey := teamMembershipTupleKey(teamID, uid)
		if existingID, ok := r.teamMembershipsByTuple[tupleKey]; ok {
			delete(r.teamMembershipsByTuple, tupleKey)
			delete(r.teamMemberships, existingID)
			removed++
		}
	}
	return results, removed, nil
}

func (r *MemoryRepository) RotateKEKsTransactionally(_ context.Context, rewrap func(batch KEKRotationBatch) (KEKRotationBatch, error)) (KEKRotationSummary, error) {
	var summary KEKRotationSummary
	if rewrap == nil {
		return summary, fmt.Errorf("rewrap callback is required")
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	batch := KEKRotationBatch{
		Credentials:       make([]*domain.ProviderCredential, 0, len(r.credentials)),
		MCPServers:        make([]*domain.MCPServer, 0, len(r.mcpServers)),
		A2AAgents:         make([]*domain.A2AAgent, 0, len(r.a2aAgents)),
		Guardrails:        make([]*domain.GuardrailDefinition, 0, len(r.guardrailDefs)),
		StagedVirtualKeys: make([]*domain.VirtualKey, 0),
	}
	for _, c := range r.credentials {
		if c == nil || len(c.EncryptedDEK) == 0 {
			continue
		}
		cp := *c
		cp.EncryptedAPIKey = slices.Clone(c.EncryptedAPIKey)
		cp.DataNonce = slices.Clone(c.DataNonce)
		cp.EncryptedDEK = slices.Clone(c.EncryptedDEK)
		cp.DEKNonce = slices.Clone(c.DEKNonce)
		batch.Credentials = append(batch.Credentials, &cp)
	}
	for _, s := range r.mcpServers {
		if s == nil || strings.TrimSpace(s.EncryptedAuthDEK) == "" {
			continue
		}
		cp := *s
		batch.MCPServers = append(batch.MCPServers, &cp)
	}
	for _, a := range r.a2aAgents {
		if a == nil || strings.TrimSpace(a.EncryptedAuthDEK) == "" {
			continue
		}
		cp := *a
		batch.A2AAgents = append(batch.A2AAgents, &cp)
	}
	for _, g := range r.guardrailDefs {
		if g == nil || strings.TrimSpace(g.EncryptedDEK) == "" {
			continue
		}
		batch.Guardrails = append(batch.Guardrails, cloneGuardrailDefinition(g))
	}
	for _, vk := range r.keysByID {
		if vk == nil || strings.TrimSpace(vk.StagedKeyDEK) == "" {
			continue
		}
		batch.StagedVirtualKeys = append(batch.StagedVirtualKeys, cloneVirtualKey(vk))
	}

	updated, err := rewrap(batch)
	if err != nil {
		return KEKRotationSummary{}, err
	}

	now := time.Now().UTC()
	for _, c := range updated.Credentials {
		if c == nil || c.ID == "" {
			continue
		}
		if _, ok := r.credentials[c.ID]; ok {
			cp := *c
			cp.UpdatedAt = now
			cp.DecryptedAPIKey = ""
			r.credentials[c.ID] = &cp
			summary.CredentialsRewrapped++
		}
	}
	for _, s := range updated.MCPServers {
		if s == nil || s.ID == "" {
			continue
		}
		if existing, ok := r.mcpServers[s.ID]; ok {
			cp := *existing
			cp.EncryptedAuthDEK = s.EncryptedAuthDEK
			cp.ConfigVersion++
			cp.UpdatedAt = now
			r.mcpServers[s.ID] = &cp
			summary.MCPServersRewrapped++
		}
	}
	for _, a := range updated.A2AAgents {
		if a == nil || a.ID == "" {
			continue
		}
		if existing, ok := r.a2aAgents[a.ID]; ok {
			cp := *existing
			cp.EncryptedAuthDEK = a.EncryptedAuthDEK
			cp.UpdatedAt = now
			r.a2aAgents[a.ID] = &cp
			summary.A2AAgentsRewrapped++
		}
	}
	for _, g := range updated.Guardrails {
		if g != nil && g.ID != "" {
			if existing, ok := r.guardrailDefs[g.ID]; ok {
				cp := cloneGuardrailDefinition(existing)
				cp.EncryptedDEK = g.EncryptedDEK
				cp.UpdatedAt = now
				r.guardrailDefs[g.ID] = cp
				summary.GuardrailsRewrapped++
			}
		}
	}
	for _, vk := range updated.StagedVirtualKeys {
		if vk == nil || vk.ID == "" {
			continue
		}
		if existing, ok := r.keysByID[vk.ID]; ok {
			cp := cloneVirtualKey(existing)
			cp.StagedKeyDEK = vk.StagedKeyDEK
			r.keysByID[vk.ID] = cp
			if cp.KeyHash != "" {
				r.keysByHash[cp.KeyHash] = cp
			}
			summary.StagedVirtualKeysRewrapped++
		}
	}
	return summary, nil
}

func (r *MemoryRepository) CreateProject(_ context.Context, p *domain.Project) error {
	if err := normalizeProject(p); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	tupleKey := projectNameTupleKey(p.TeamID, p.Name)
	if _, exists := r.projectsByTeamName[tupleKey]; exists {
		return fmt.Errorf("project %q already exists in team %q: %w", p.Name, p.TeamID, ErrConflict)
	}
	if p.ID == "" {
		p.ID = uuid.NewString()
	} else if _, exists := r.projects[p.ID]; exists {
		return fmt.Errorf("project %q already exists: %w", p.ID, ErrConflict)
	}
	now := time.Now().UTC()
	if p.CreatedAt.IsZero() {
		p.CreatedAt = now
	}
	p.UpdatedAt = now
	r.projects[p.ID] = cloneProject(p)
	r.projectsByTeamName[tupleKey] = p.ID
	return nil
}

func (r *MemoryRepository) GetProject(_ context.Context, id string) (*domain.Project, error) {
	id = strings.TrimSpace(id)
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.projects[id]
	if !ok {
		return nil, fmt.Errorf("project %q %w", id, ErrNotFound)
	}
	return cloneProject(p), nil
}

func (r *MemoryRepository) ListProjects(_ context.Context, orgID, teamID string) ([]*domain.Project, error) {
	orgID = strings.TrimSpace(orgID)
	teamID = strings.TrimSpace(teamID)
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []*domain.Project
	for _, p := range r.projects {
		if orgID != "" && p.OrgID != orgID {
			continue
		}
		if teamID != "" && p.TeamID != teamID {
			continue
		}
		out = append(out, cloneProject(p))
	}
	sortProjects(out)
	return out, nil
}

func (r *MemoryRepository) UpdateProject(_ context.Context, p *domain.Project) error {
	if err := normalizeProject(p); err != nil {
		return err
	}
	if p.ID == "" {
		return fmt.Errorf("project id is required")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	existing, ok := r.projects[p.ID]
	if !ok {
		return fmt.Errorf("project %q %w", p.ID, ErrNotFound)
	}
	newTupleKey := projectNameTupleKey(p.TeamID, p.Name)
	if otherID, exists := r.projectsByTeamName[newTupleKey]; exists && otherID != p.ID {
		return fmt.Errorf("project %q already exists in team %q: %w", p.Name, p.TeamID, ErrConflict)
	}
	oldTupleKey := projectNameTupleKey(existing.TeamID, existing.Name)
	if oldTupleKey != newTupleKey {
		delete(r.projectsByTeamName, oldTupleKey)
	}
	if p.CreatedAt.IsZero() {
		p.CreatedAt = existing.CreatedAt
	}
	p.UpdatedAt = time.Now().UTC()
	r.projects[p.ID] = cloneProject(p)
	r.projectsByTeamName[newTupleKey] = p.ID
	return nil
}

func (r *MemoryRepository) DeleteProject(_ context.Context, id string) error {
	id = strings.TrimSpace(id)
	r.mu.Lock()
	defer r.mu.Unlock()
	p, ok := r.projects[id]
	if !ok {
		return fmt.Errorf("project %q %w", id, ErrNotFound)
	}
	delete(r.projectsByTeamName, projectNameTupleKey(p.TeamID, p.Name))
	delete(r.projects, id)
	for _, vk := range r.keysByID {
		if vk.ProjectID == id {
			vk.ProjectID = ""
		}
	}
	return nil
}

func (r *MemoryRepository) GetUserByOrgAndOIDCSubject(ctx context.Context, orgID, subject string) (*domain.User, error) {
	return r.GetUserByOIDCIdentity(ctx, orgID, "", subject)
}

func (r *MemoryRepository) GetUserByOIDCIdentity(_ context.Context, orgID, issuer, subject string) (*domain.User, error) {
	if subject == "" || (orgID == "" && issuer != "") {
		return nil, fmt.Errorf("user with org_id %q issuer %q and oidc_subject %q %w", orgID, issuer, subject, ErrNotFound)
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	var matched *domain.User
	for _, u := range r.users {
		if (orgID == "" || u.OrgID == orgID) && u.OIDCIssuer == issuer && u.OIDCSubject == subject {
			if matched != nil {
				return nil, fmt.Errorf("multiple users share oidc identity: %w", ErrConflict)
			}
			matched = cloneUser(u)
		}
	}
	if matched == nil {
		return nil, fmt.Errorf("user with org_id %q issuer %q and oidc_subject %q %w", orgID, issuer, subject, ErrNotFound)
	}
	return matched, nil
}

func (r *MemoryRepository) GetUserByEmail(ctx context.Context, email string) (*domain.User, error) {
	email = strings.TrimSpace(email)
	if email == "" {
		return nil, fmt.Errorf("user with email %q %w", email, ErrNotFound)
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, u := range r.users {
		if strings.EqualFold(u.Email, email) {
			return cloneUser(u), nil
		}
	}
	return nil, fmt.Errorf("user with email %q %w", email, ErrNotFound)
}

func (r *MemoryRepository) GetUserBySCIMExternalID(ctx context.Context, orgID, externalID string) (*domain.User, error) {
	orgID = strings.TrimSpace(orgID)
	externalID = strings.TrimSpace(externalID)
	if orgID == "" || externalID == "" {
		return nil, fmt.Errorf("user with org_id %q and scim_external_id %q %w", orgID, externalID, ErrNotFound)
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, u := range r.users {
		if u.OrgID == orgID && u.SCIMExternalID == externalID {
			return cloneUser(u), nil
		}
	}
	return nil, fmt.Errorf("user with org_id %q and scim_external_id %q %w", orgID, externalID, ErrNotFound)
}

func (r *MemoryRepository) GetOrCreateUserByOIDCSubject(ctx context.Context, user *domain.User) (*domain.User, bool, error) {
	if user == nil || strings.TrimSpace(user.OrgID) == "" {
		return nil, false, fmt.Errorf("org_id is required to provision user")
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	if user.OIDCSubject != "" {
		for _, u := range r.users {
			if u.OrgID == user.OrgID && u.OIDCIssuer == user.OIDCIssuer && u.OIDCSubject == user.OIDCSubject {
				cp := *u
				return &cp, false, nil
			}
		}
	}
	if user.Email != "" {
		for _, u := range r.users {
			if strings.EqualFold(u.Email, user.Email) {
				if u.OrgID != user.OrgID {
					return nil, false, fmt.Errorf("email %q already belongs to another organization: %w", user.Email, ErrConflict)
				}
				if u.OIDCIssuer != "" || user.OIDCIssuer != "" || (u.OIDCSubject != "" && user.OIDCSubject != "" && u.OIDCSubject != user.OIDCSubject) {
					return nil, false, fmt.Errorf("email %q is bound to another OIDC identity: %w", user.Email, ErrConflict)
				}
				cp := *u
				return &cp, false, nil
			}
		}
	}

	cp := *user
	if cp.ID == "" {
		cp.ID = uuid.NewString()
	}
	if cp.IsActive && strings.TrimSpace(cp.SCIMExternalID) == "" {
		cp.SCIMActive = true
	}
	now := time.Now().UTC()
	cp.BudgetResetPeriod, cp.BudgetResetAt = resolveBudgetResetSchedule(cp.BudgetResetPeriod, cp.BudgetResetAt, now)
	cp.CreatedAt = now
	cp.UpdatedAt = now
	r.users[cp.ID] = &cp
	out := cp
	return &out, true, nil
}

func jwtMappingTupleKey(orgID, issuer, claimName, claimValue string) string {
	return orgID + "\x00" + issuer + "\x00" + claimName + "\x00" + claimValue
}

func (r *MemoryRepository) CreateJWTKeyMapping(ctx context.Context, mapping *domain.JWTKeyMapping) error {
	if mapping == nil {
		return fmt.Errorf("jwt key mapping is required")
	}
	if strings.TrimSpace(mapping.OrgID) == "" ||
		strings.TrimSpace(mapping.Issuer) == "" ||
		strings.TrimSpace(mapping.ClaimName) == "" ||
		strings.TrimSpace(mapping.ClaimValue) == "" ||
		strings.TrimSpace(mapping.VirtualKeyID) == "" {
		return fmt.Errorf("org_id, issuer, claim_name, claim_value, and virtual_key_id are required")
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	tupleKey := jwtMappingTupleKey(mapping.OrgID, mapping.Issuer, mapping.ClaimName, mapping.ClaimValue)
	if _, exists := r.jwtKeyMappingsByTuple[tupleKey]; exists {
		return fmt.Errorf("jwt key mapping already exists for (%s, %s, %s, %s): %w", mapping.OrgID, mapping.Issuer, mapping.ClaimName, mapping.ClaimValue, ErrConflict)
	}
	if mapping.ID == "" {
		mapping.ID = uuid.NewString()
	}
	if mapping.CreatedAt.IsZero() {
		mapping.CreatedAt = time.Now().UTC()
	}
	cp := *mapping
	r.jwtKeyMappings[cp.ID] = &cp
	r.jwtKeyMappingsByTuple[tupleKey] = cp.ID
	return nil
}

func (r *MemoryRepository) GetJWTKeyMapping(ctx context.Context, id string) (*domain.JWTKeyMapping, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	m, ok := r.jwtKeyMappings[id]
	if !ok {
		return nil, fmt.Errorf("jwt key mapping %q %w", id, ErrNotFound)
	}
	cp := *m
	return &cp, nil
}

func (r *MemoryRepository) ListJWTKeyMappings(ctx context.Context, orgID string) ([]*domain.JWTKeyMapping, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []*domain.JWTKeyMapping
	for _, m := range r.jwtKeyMappings {
		if orgID == "" || m.OrgID == orgID {
			cp := *m
			out = append(out, &cp)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.Before(out[j].CreatedAt)
		}
		return out[i].ID < out[j].ID
	})
	return out, nil
}

func (r *MemoryRepository) DeleteJWTKeyMapping(ctx context.Context, id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	m, ok := r.jwtKeyMappings[id]
	if !ok {
		return fmt.Errorf("jwt key mapping %q %w", id, ErrNotFound)
	}
	delete(r.jwtKeyMappingsByTuple, jwtMappingTupleKey(m.OrgID, m.Issuer, m.ClaimName, m.ClaimValue))
	delete(r.jwtKeyMappings, id)
	return nil
}

func (r *MemoryRepository) ResolveJWTKeyMapping(ctx context.Context, issuer, claimName, claimValue string) (*domain.JWTKeyMapping, error) {
	return r.ResolveJWTKeyMappingForOrg(ctx, "", issuer, claimName, claimValue)
}

func (r *MemoryRepository) ResolveJWTKeyMappingForOrg(ctx context.Context, orgID, issuer, claimName, claimValue string) (*domain.JWTKeyMapping, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	orgID = strings.TrimSpace(orgID)
	if orgID != "" {
		id, ok := r.jwtKeyMappingsByTuple[jwtMappingTupleKey(orgID, issuer, claimName, claimValue)]
		if !ok {
			return nil, fmt.Errorf("jwt key mapping %w", ErrNotFound)
		}
		m, ok := r.jwtKeyMappings[id]
		if !ok {
			return nil, fmt.Errorf("jwt key mapping %w", ErrNotFound)
		}
		cp := *m
		return &cp, nil
	}
	for _, m := range r.jwtKeyMappings {
		if m != nil && m.Issuer == issuer && m.ClaimName == claimName && m.ClaimValue == claimValue {
			cp := *m
			return &cp, nil
		}
	}
	return nil, fmt.Errorf("jwt key mapping %w", ErrNotFound)
}

func cloneUserCredential(cred *domain.UserCredential) *domain.UserCredential {
	if cred == nil {
		return nil
	}
	cp := *cred
	if cred.LockedUntil != nil {
		t := *cred.LockedUntil
		cp.LockedUntil = &t
	}
	return &cp
}

func cloneOperatorSession(sess *domain.OperatorSession) *domain.OperatorSession {
	if sess == nil {
		return nil
	}
	cp := *sess
	if sess.RevokedAt != nil {
		t := *sess.RevokedAt
		cp.RevokedAt = &t
	}
	return &cp
}

func (r *MemoryRepository) UpsertUserPassword(ctx context.Context, userID, passwordHash string, resetRequired bool) error {
	userID = strings.TrimSpace(userID)
	passwordHash = strings.TrimSpace(passwordHash)
	if userID == "" {
		return fmt.Errorf("user_id is required")
	}
	if passwordHash == "" {
		return fmt.Errorf("password_hash is required")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.userCredentials[userID] = &domain.UserCredential{
		UserID:                userID,
		PasswordHash:          passwordHash,
		PasswordResetRequired: resetRequired,
		FailedAttempts:        0,
		LockedUntil:           nil,
		UpdatedAt:             time.Now().UTC(),
	}
	return nil
}

func (r *MemoryRepository) GetUserCredential(ctx context.Context, userID string) (*domain.UserCredential, error) {
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return nil, fmt.Errorf("user credential for %q %w", userID, ErrNotFound)
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	cred, ok := r.userCredentials[userID]
	if !ok || cred == nil {
		return nil, fmt.Errorf("user credential for %q %w", userID, ErrNotFound)
	}
	return cloneUserCredential(cred), nil
}

func (r *MemoryRepository) UpdateUserLoginFailure(ctx context.Context, userID string, failedAttempts int, lockedUntil *time.Time) error {
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return fmt.Errorf("user_id is required")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	cred, ok := r.userCredentials[userID]
	if !ok || cred == nil {
		return fmt.Errorf("user credential for %q %w", userID, ErrNotFound)
	}
	cred.FailedAttempts = failedAttempts
	if lockedUntil != nil {
		t := lockedUntil.UTC()
		cred.LockedUntil = &t
	} else {
		cred.LockedUntil = nil
	}
	cred.UpdatedAt = time.Now().UTC()
	return nil
}

func (r *MemoryRepository) CreateOperatorSession(ctx context.Context, session *domain.OperatorSession) error {
	if session == nil {
		return fmt.Errorf("operator session is required")
	}
	if strings.TrimSpace(session.UserID) == "" ||
		strings.TrimSpace(session.OrgID) == "" ||
		strings.TrimSpace(session.Role) == "" ||
		strings.TrimSpace(session.CSRFToken) == "" ||
		session.ExpiresAt.IsZero() {
		return fmt.Errorf("user_id, org_id, role, csrf_token, and expires_at are required")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if strings.TrimSpace(session.ID) == "" {
		session.ID = uuid.NewString()
	}
	if session.CreatedAt.IsZero() {
		session.CreatedAt = time.Now().UTC()
	}
	r.operatorSessions[session.ID] = cloneOperatorSession(session)
	return nil
}

func (r *MemoryRepository) GetOperatorSession(ctx context.Context, id string) (*domain.OperatorSession, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return nil, fmt.Errorf("operator session %q %w", id, ErrNotFound)
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	sess, ok := r.operatorSessions[id]
	if !ok || sess == nil {
		return nil, fmt.Errorf("operator session %q %w", id, ErrNotFound)
	}
	return cloneOperatorSession(sess), nil
}

func (r *MemoryRepository) RevokeOperatorSession(ctx context.Context, id string, revokedAt time.Time) error {
	id = strings.TrimSpace(id)
	if id == "" {
		return fmt.Errorf("operator session id is required")
	}
	if revokedAt.IsZero() {
		revokedAt = time.Now().UTC()
	} else {
		revokedAt = revokedAt.UTC()
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	sess, ok := r.operatorSessions[id]
	if !ok || sess == nil {
		return fmt.Errorf("operator session %q %w", id, ErrNotFound)
	}
	if sess.RevokedAt == nil {
		t := revokedAt
		sess.RevokedAt = &t
	}
	return nil
}

func (r *MemoryRepository) RevokeAllUserSessions(ctx context.Context, userID string, revokedAt time.Time) error {
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return fmt.Errorf("user_id is required")
	}
	if revokedAt.IsZero() {
		revokedAt = time.Now().UTC()
	} else {
		revokedAt = revokedAt.UTC()
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, sess := range r.operatorSessions {
		if sess != nil && sess.UserID == userID && sess.RevokedAt == nil {
			t := revokedAt
			sess.RevokedAt = &t
		}
	}
	return nil
}
