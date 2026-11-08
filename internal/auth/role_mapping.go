package auth

import (
	"slices"
	"strings"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
)

const (
	// RoleMappingStrategyHighestPrivilege selects the highest-privilege GoRoute role matched across all groups.
	RoleMappingStrategyHighestPrivilege = "highest_privilege"
	// RoleMappingStrategyFirstMatch selects the first matching rule in configured order.
	RoleMappingStrategyFirstMatch = "first_match"
)

// GroupRoleMappingRule maps an IdP group or realm-role string to a GoRoute role.
type GroupRoleMappingRule struct {
	Group string `yaml:"group" json:"group"`
	Role  string `yaml:"role" json:"role"`
}

func rolePrivilegeRank(role domain.Role) int {
	switch role {
	case domain.RolePlatformAdmin:
		return 70
	case domain.RoleOrgAdmin:
		return 60
	case domain.RoleTeamAdmin:
		return 50
	case domain.RoleOrgViewer:
		return 40
	case domain.RoleDeveloper:
		return 30
	case domain.RoleServiceAccount:
		return 20
	case domain.RoleViewer:
		return 10
	default:
		return 0
	}
}

// ResolveMappedRole determines the effective GoRoute role from IdP group memberships,
// declarative group_role_mappings, direct role claim, and default_role fallback.
//
// Security invariant: platform_admin is NEVER granted from external claims or group
// mappings unless allowPrivilegedClaims is true.
func ResolveMappedRole(
	directRole string,
	groups []string,
	mappings []GroupRoleMappingRule,
	strategy string,
	defaultRole string,
	allowPrivilegedClaims bool,
) domain.Role {
	strategy = strings.ToLower(strings.TrimSpace(strategy))
	if strategy == "" {
		strategy = RoleMappingStrategyHighestPrivilege
	}

	if len(groups) > 0 && len(mappings) > 0 {
		groupSet := make(map[string]struct{}, len(groups))
		for _, g := range groups {
			if trimmed := strings.TrimSpace(g); trimmed != "" {
				groupSet[trimmed] = struct{}{}
			}
		}

		var bestRole domain.Role
		bestRank := -1
		for _, rule := range mappings {
			grp := strings.TrimSpace(rule.Group)
			if grp == "" {
				continue
			}
			if _, ok := groupSet[grp]; !ok {
				continue
			}
			candidate, ok := parseValidDomainRole(rule.Role)
			if !ok {
				continue
			}
			if candidate == domain.RolePlatformAdmin && !allowPrivilegedClaims {
				continue
			}
			if strategy == RoleMappingStrategyFirstMatch {
				return candidate
			}
			rank := rolePrivilegeRank(candidate)
			if rank > bestRank {
				bestRank = rank
				bestRole = candidate
			}
		}
		if bestRole != "" {
			return bestRole
		}
	}

	if role, ok := parseValidDomainRole(directRole); ok {
		if role != domain.RolePlatformAdmin || allowPrivilegedClaims {
			return role
		}
	}
	if role, ok := parseValidDomainRole(defaultRole); ok {
		return role
	}
	return domain.RoleDeveloper
}

// ResolveMappedTeamID resolves the user's target team_id from explicit team_ids claims,
// declarative group_team_mappings (iterated deterministically), and default_team_id fallback.
func ResolveMappedTeamID(
	claimTeamIDs []string,
	groups []string,
	groupTeamMappings map[string]string,
	defaultTeamID string,
) string {
	for _, tid := range claimTeamIDs {
		if trimmed := strings.TrimSpace(tid); trimmed != "" {
			return trimmed
		}
	}
	if len(groups) > 0 && len(groupTeamMappings) > 0 {
		sortedGroups := slices.Clone(groups)
		slices.Sort(sortedGroups)
		for _, g := range sortedGroups {
			if mapped := strings.TrimSpace(groupTeamMappings[strings.TrimSpace(g)]); mapped != "" {
				return mapped
			}
		}
	}
	return strings.TrimSpace(defaultTeamID)
}
