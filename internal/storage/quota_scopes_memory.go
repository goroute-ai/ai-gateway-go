package storage

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
)

func (r *MemoryRepository) UpsertEndUser(_ context.Context, eu *domain.EndUser) error {
	now := time.Now().UTC()
	if err := normalizeEndUser(eu, now); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	tupleKey := endUserTupleKey(eu.OrgID, eu.EndUserID)
	if existingID, ok := r.endUsersByTuple[tupleKey]; ok {
		existing := r.endUsers[existingID]
		if eu.ID != "" && eu.ID != existing.ID {
			if _, idExists := r.endUsers[eu.ID]; idExists {
				return fmt.Errorf("end_user %q already exists: %w", eu.ID, ErrConflict)
			}
		}
		eu.ID = existing.ID
		eu.CreatedAt = existing.CreatedAt
		if existing.SpentMicros > eu.SpentMicros {
			eu.SpentMicros = existing.SpentMicros
		}
		eu.UpdatedAt = now
		r.endUsers[existing.ID] = eu.Clone()
		return nil
	}

	if eu.ID == "" {
		eu.ID = uuid.NewString()
	} else if _, exists := r.endUsers[eu.ID]; exists {
		return fmt.Errorf("end_user %q already exists: %w", eu.ID, ErrConflict)
	}
	if eu.CreatedAt.IsZero() {
		eu.CreatedAt = now
	}
	eu.UpdatedAt = now
	r.endUsers[eu.ID] = eu.Clone()
	r.endUsersByTuple[tupleKey] = eu.ID
	return nil
}

func (r *MemoryRepository) GetOrCreateEndUser(_ context.Context, orgID, endUserID string) (*domain.EndUser, error) {
	orgID = strings.TrimSpace(orgID)
	endUserID = strings.TrimSpace(endUserID)
	if orgID == "" || endUserID == "" {
		return nil, fmt.Errorf("org_id and end_user_id are required")
	}

	tupleKey := endUserTupleKey(orgID, endUserID)
	r.mu.RLock()
	if id, ok := r.endUsersByTuple[tupleKey]; ok {
		if eu, exists := r.endUsers[id]; exists {
			cp := eu.Clone()
			r.mu.RUnlock()
			return cp, nil
		}
	}
	r.mu.RUnlock()

	r.mu.Lock()
	defer r.mu.Unlock()
	if id, ok := r.endUsersByTuple[tupleKey]; ok {
		if eu, exists := r.endUsers[id]; exists {
			return eu.Clone(), nil
		}
	}

	now := time.Now().UTC()
	eu := &domain.EndUser{
		ID:        uuid.NewString(),
		OrgID:     orgID,
		EndUserID: endUserID,
		IsActive:  true,
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := normalizeEndUser(eu, now); err != nil {
		return nil, err
	}
	r.endUsers[eu.ID] = eu.Clone()
	r.endUsersByTuple[tupleKey] = eu.ID
	return eu.Clone(), nil
}

func (r *MemoryRepository) GetEndUser(_ context.Context, id string) (*domain.EndUser, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	eu, ok := r.endUsers[strings.TrimSpace(id)]
	if !ok {
		return nil, fmt.Errorf("end_user %q %w", id, ErrNotFound)
	}
	return eu.Clone(), nil
}

func (r *MemoryRepository) GetEndUserByExternalID(_ context.Context, orgID, endUserID string) (*domain.EndUser, error) {
	orgID = strings.TrimSpace(orgID)
	endUserID = strings.TrimSpace(endUserID)
	r.mu.RLock()
	defer r.mu.RUnlock()
	id, ok := r.endUsersByTuple[endUserTupleKey(orgID, endUserID)]
	if !ok {
		return nil, fmt.Errorf("end_user (%s, %s) %w", orgID, endUserID, ErrNotFound)
	}
	eu, exists := r.endUsers[id]
	if !exists {
		return nil, fmt.Errorf("end_user (%s, %s) %w", orgID, endUserID, ErrNotFound)
	}
	return eu.Clone(), nil
}

func (r *MemoryRepository) ListEndUsers(_ context.Context, filter EndUserFilter) ([]*domain.EndUser, error) {
	orgID := strings.TrimSpace(filter.OrgID)
	endUserID := strings.TrimSpace(filter.EndUserID)

	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []*domain.EndUser
	for _, eu := range r.endUsers {
		if orgID != "" && eu.OrgID != orgID {
			continue
		}
		if endUserID != "" && eu.EndUserID != endUserID {
			continue
		}
		if filter.ActiveOnly && !eu.IsActive {
			continue
		}
		out = append(out, eu.Clone())
	}
	sortEndUsers(out)
	return out, nil
}

func (r *MemoryRepository) DeleteEndUser(_ context.Context, id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	eu, ok := r.endUsers[strings.TrimSpace(id)]
	if !ok {
		return fmt.Errorf("end_user %q %w", id, ErrNotFound)
	}
	delete(r.endUsersByTuple, endUserTupleKey(eu.OrgID, eu.EndUserID))
	delete(r.endUsers, eu.ID)
	return nil
}

func (r *MemoryRepository) IncrementEndUserSpend(_ context.Context, orgID, endUserID string, deltaMicros int64) error {
	orgID = strings.TrimSpace(orgID)
	endUserID = strings.TrimSpace(endUserID)
	if orgID == "" || endUserID == "" {
		return fmt.Errorf("org_id and end_user_id are required")
	}
	if deltaMicros < 0 {
		return fmt.Errorf("delta_micros must be non-negative")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	id, ok := r.endUsersByTuple[endUserTupleKey(orgID, endUserID)]
	if !ok {
		return fmt.Errorf("end_user (%s, %s) %w", orgID, endUserID, ErrNotFound)
	}
	eu := r.endUsers[id]
	eu.SpentMicros += deltaMicros
	eu.UpdatedAt = time.Now().UTC()
	return nil
}

func (r *MemoryRepository) UpsertTag(_ context.Context, tag *domain.Tag) error {
	now := time.Now().UTC()
	if err := normalizeTag(tag, now); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	tupleKey := tagTupleKey(tag.OrgID, tag.Tag)
	if existingID, ok := r.tagsByTuple[tupleKey]; ok {
		existing := r.tags[existingID]
		if tag.ID != "" && tag.ID != existing.ID {
			if _, idExists := r.tags[tag.ID]; idExists {
				return fmt.Errorf("tag %q already exists: %w", tag.ID, ErrConflict)
			}
		}
		tag.ID = existing.ID
		tag.CreatedAt = existing.CreatedAt
		if existing.SpentMicros > tag.SpentMicros {
			tag.SpentMicros = existing.SpentMicros
		}
		tag.UpdatedAt = now
		r.tags[existing.ID] = tag.Clone()
		return nil
	}

	if tag.ID == "" {
		tag.ID = uuid.NewString()
	} else if _, exists := r.tags[tag.ID]; exists {
		return fmt.Errorf("tag %q already exists: %w", tag.ID, ErrConflict)
	}
	if tag.CreatedAt.IsZero() {
		tag.CreatedAt = now
	}
	tag.UpdatedAt = now
	r.tags[tag.ID] = tag.Clone()
	r.tagsByTuple[tupleKey] = tag.ID
	return nil
}

func (r *MemoryRepository) GetTag(_ context.Context, id string) (*domain.Tag, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	t, ok := r.tags[strings.TrimSpace(id)]
	if !ok {
		return nil, fmt.Errorf("tag %q %w", id, ErrNotFound)
	}
	return t.Clone(), nil
}

func (r *MemoryRepository) GetTagByName(_ context.Context, orgID, tagName string) (*domain.Tag, error) {
	orgID = strings.TrimSpace(orgID)
	tagName = strings.TrimSpace(tagName)
	r.mu.RLock()
	defer r.mu.RUnlock()
	id, ok := r.tagsByTuple[tagTupleKey(orgID, tagName)]
	if !ok {
		return nil, fmt.Errorf("tag (%s, %s) %w", orgID, tagName, ErrNotFound)
	}
	t, exists := r.tags[id]
	if !exists {
		return nil, fmt.Errorf("tag (%s, %s) %w", orgID, tagName, ErrNotFound)
	}
	return t.Clone(), nil
}

func (r *MemoryRepository) ListTags(_ context.Context, filter TagFilter) ([]*domain.Tag, error) {
	orgID := strings.TrimSpace(filter.OrgID)
	tagName := strings.TrimSpace(filter.Tag)

	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []*domain.Tag
	for _, t := range r.tags {
		if orgID != "" && t.OrgID != orgID {
			continue
		}
		if tagName != "" && t.Tag != tagName {
			continue
		}
		if filter.ActiveOnly && !t.IsActive {
			continue
		}
		out = append(out, t.Clone())
	}
	sortTags(out)
	return out, nil
}

func (r *MemoryRepository) DeleteTag(_ context.Context, id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	t, ok := r.tags[strings.TrimSpace(id)]
	if !ok {
		return fmt.Errorf("tag %q %w", id, ErrNotFound)
	}
	delete(r.tagsByTuple, tagTupleKey(t.OrgID, t.Tag))
	delete(r.tags, t.ID)
	return nil
}

func (r *MemoryRepository) IncrementTagSpend(_ context.Context, orgID, tagName string, deltaMicros int64) error {
	orgID = strings.TrimSpace(orgID)
	tagName = strings.TrimSpace(tagName)
	if orgID == "" || tagName == "" {
		return fmt.Errorf("org_id and tag are required")
	}
	if deltaMicros < 0 {
		return fmt.Errorf("delta_micros must be non-negative")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	id, ok := r.tagsByTuple[tagTupleKey(orgID, tagName)]
	if !ok {
		return fmt.Errorf("tag (%s, %s) %w", orgID, tagName, ErrNotFound)
	}
	t := r.tags[id]
	t.SpentMicros += deltaMicros
	t.UpdatedAt = time.Now().UTC()
	return nil
}

func (r *MemoryRepository) groupMembersLocked(groupID string) []*domain.ModelAccessGroupMember {
	var out []*domain.ModelAccessGroupMember
	for _, m := range r.modelAccessGroupMembers {
		if m.GroupID == groupID {
			out = append(out, m.Clone())
		}
	}
	sortModelAccessGroupMembers(out)
	return out
}

func (r *MemoryRepository) UpsertModelAccessGroup(_ context.Context, group *domain.ModelAccessGroup) error {
	now := time.Now().UTC()
	if err := normalizeModelAccessGroup(group, now); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	tupleKey := modelAccessGroupTupleKey(group.OrgID, group.Name)
	if existingID, ok := r.modelAccessGroupsByTuple[tupleKey]; ok {
		existing := r.modelAccessGroups[existingID]
		if group.ID != "" && group.ID != existing.ID {
			if _, idExists := r.modelAccessGroups[group.ID]; idExists {
				return fmt.Errorf("model_access_group %q already exists: %w", group.ID, ErrConflict)
			}
		}
		group.ID = existing.ID
		group.CreatedAt = existing.CreatedAt
		if existing.SpentMicros > group.SpentMicros {
			group.SpentMicros = existing.SpentMicros
		}
		group.UpdatedAt = now
		stored := group.Clone()
		stored.Members = nil
		r.modelAccessGroups[existing.ID] = stored
		group.Members = r.groupMembersLocked(existing.ID)
		return nil
	}

	if group.ID == "" {
		group.ID = uuid.NewString()
	} else if _, exists := r.modelAccessGroups[group.ID]; exists {
		return fmt.Errorf("model_access_group %q already exists: %w", group.ID, ErrConflict)
	}
	if group.CreatedAt.IsZero() {
		group.CreatedAt = now
	}
	group.UpdatedAt = now
	stored := group.Clone()
	stored.Members = nil
	r.modelAccessGroups[group.ID] = stored
	r.modelAccessGroupsByTuple[tupleKey] = group.ID
	group.Members = r.groupMembersLocked(group.ID)
	return nil
}

func (r *MemoryRepository) GetModelAccessGroup(_ context.Context, id string) (*domain.ModelAccessGroup, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	g, ok := r.modelAccessGroups[strings.TrimSpace(id)]
	if !ok {
		return nil, fmt.Errorf("model_access_group %q %w", id, ErrNotFound)
	}
	cp := g.Clone()
	cp.Members = r.groupMembersLocked(g.ID)
	return cp, nil
}

func (r *MemoryRepository) GetModelAccessGroupByName(_ context.Context, orgID, name string) (*domain.ModelAccessGroup, error) {
	orgID = strings.TrimSpace(orgID)
	name = strings.TrimSpace(name)
	r.mu.RLock()
	defer r.mu.RUnlock()
	id, ok := r.modelAccessGroupsByTuple[modelAccessGroupTupleKey(orgID, name)]
	if !ok {
		return nil, fmt.Errorf("model_access_group (%s, %s) %w", orgID, name, ErrNotFound)
	}
	g, exists := r.modelAccessGroups[id]
	if !exists {
		return nil, fmt.Errorf("model_access_group (%s, %s) %w", orgID, name, ErrNotFound)
	}
	cp := g.Clone()
	cp.Members = r.groupMembersLocked(g.ID)
	return cp, nil
}

func (r *MemoryRepository) ListModelAccessGroups(_ context.Context, filter ModelAccessGroupFilter) ([]*domain.ModelAccessGroup, error) {
	orgID := strings.TrimSpace(filter.OrgID)
	name := strings.TrimSpace(filter.Name)

	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []*domain.ModelAccessGroup
	for _, g := range r.modelAccessGroups {
		if orgID != "" && g.OrgID != orgID {
			continue
		}
		if name != "" && g.Name != name {
			continue
		}
		if filter.ActiveOnly && !g.IsActive {
			continue
		}
		cp := g.Clone()
		cp.Members = r.groupMembersLocked(g.ID)
		out = append(out, cp)
	}
	sortModelAccessGroups(out)
	return out, nil
}

func (r *MemoryRepository) DeleteModelAccessGroup(_ context.Context, id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	g, ok := r.modelAccessGroups[strings.TrimSpace(id)]
	if !ok {
		return fmt.Errorf("model_access_group %q %w", id, ErrNotFound)
	}
	for mid, m := range r.modelAccessGroupMembers {
		if m.GroupID == g.ID {
			delete(r.modelAccessGroupMembersByTuple, modelAccessGroupMemberTupleKey(m.GroupID, m.MemberType, m.MemberID))
			delete(r.modelAccessGroupMembers, mid)
		}
	}
	delete(r.modelAccessGroupsByTuple, modelAccessGroupTupleKey(g.OrgID, g.Name))
	delete(r.modelAccessGroups, g.ID)
	return nil
}

func (r *MemoryRepository) IncrementModelAccessGroupSpend(_ context.Context, groupID string, deltaMicros int64) error {
	groupID = strings.TrimSpace(groupID)
	if groupID == "" {
		return fmt.Errorf("group_id is required")
	}
	if deltaMicros < 0 {
		return fmt.Errorf("delta_micros must be non-negative")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	g, ok := r.modelAccessGroups[groupID]
	if !ok {
		return fmt.Errorf("model_access_group %q %w", groupID, ErrNotFound)
	}
	g.SpentMicros += deltaMicros
	g.UpdatedAt = time.Now().UTC()
	return nil
}

func (r *MemoryRepository) AddModelAccessGroupMember(_ context.Context, member *domain.ModelAccessGroupMember) error {
	if err := normalizeModelAccessGroupMember(member); err != nil {
		return err
	}
	now := time.Now().UTC()
	r.mu.Lock()
	defer r.mu.Unlock()

	g, ok := r.modelAccessGroups[member.GroupID]
	if !ok {
		return fmt.Errorf("model_access_group %q %w", member.GroupID, ErrNotFound)
	}
	if g.OrgID != member.OrgID {
		return fmt.Errorf("member org_id %q does not match group org_id %q", member.OrgID, g.OrgID)
	}

	tupleKey := modelAccessGroupMemberTupleKey(member.GroupID, member.MemberType, member.MemberID)
	if existingID, exists := r.modelAccessGroupMembersByTuple[tupleKey]; exists {
		existing := r.modelAccessGroupMembers[existingID]
		member.ID = existing.ID
		member.CreatedAt = existing.CreatedAt
		return nil
	}

	if member.ID == "" {
		member.ID = uuid.NewString()
	} else if _, exists := r.modelAccessGroupMembers[member.ID]; exists {
		return fmt.Errorf("model_access_group_member %q already exists: %w", member.ID, ErrConflict)
	}
	if member.CreatedAt.IsZero() {
		member.CreatedAt = now
	}
	r.modelAccessGroupMembers[member.ID] = member.Clone()
	r.modelAccessGroupMembersByTuple[tupleKey] = member.ID
	return nil
}

func (r *MemoryRepository) ListModelAccessGroupMembers(_ context.Context, groupID string) ([]*domain.ModelAccessGroupMember, error) {
	groupID = strings.TrimSpace(groupID)
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.groupMembersLocked(groupID), nil
}

func (r *MemoryRepository) ListModelAccessGroupMembersByOrg(_ context.Context, orgID string) ([]*domain.ModelAccessGroupMember, error) {
	orgID = strings.TrimSpace(orgID)
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []*domain.ModelAccessGroupMember
	for _, m := range r.modelAccessGroupMembers {
		if orgID != "" && m.OrgID != orgID {
			continue
		}
		out = append(out, m.Clone())
	}
	sortModelAccessGroupMembers(out)
	return out, nil
}

func (r *MemoryRepository) RemoveModelAccessGroupMember(_ context.Context, groupID, memberRowID string) error {
	groupID = strings.TrimSpace(groupID)
	memberRowID = strings.TrimSpace(memberRowID)
	r.mu.Lock()
	defer r.mu.Unlock()
	m, ok := r.modelAccessGroupMembers[memberRowID]
	if !ok || (groupID != "" && m.GroupID != groupID) {
		return fmt.Errorf("model_access_group_member %q %w", memberRowID, ErrNotFound)
	}
	delete(r.modelAccessGroupMembersByTuple, modelAccessGroupMemberTupleKey(m.GroupID, m.MemberType, m.MemberID))
	delete(r.modelAccessGroupMembers, memberRowID)
	return nil
}

func (r *MemoryRepository) RemoveModelAccessGroupMemberByTuple(_ context.Context, groupID string, memberType domain.ModelAccessGroupMemberType, memberID string) error {
	groupID = strings.TrimSpace(groupID)
	memberType = domain.ModelAccessGroupMemberType(strings.ToLower(strings.TrimSpace(string(memberType))))
	memberID = strings.TrimSpace(memberID)
	r.mu.Lock()
	defer r.mu.Unlock()
	tupleKey := modelAccessGroupMemberTupleKey(groupID, memberType, memberID)
	rowID, ok := r.modelAccessGroupMembersByTuple[tupleKey]
	if !ok {
		return fmt.Errorf("model_access_group_member (%s, %s, %s) %w", groupID, memberType, memberID, ErrNotFound)
	}
	delete(r.modelAccessGroupMembersByTuple, tupleKey)
	delete(r.modelAccessGroupMembers, rowID)
	return nil
}
