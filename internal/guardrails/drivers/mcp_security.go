package drivers

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/guardrails"
	"github.com/goroute-ai/ai-gateway-go/internal/security/network"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
)

const (
	// ProviderMCPSecurity is the guardrail provider identifier for validating MCP server
	// declarations and invocations against registered tenant MCPServer entries and allowlists.
	ProviderMCPSecurity = "mcp_security"

	// ProviderMCPEndUserPermission is the guardrail provider identifier for enforcing
	// per-server and per-tool end-user, role, team, and OIDC claim RBAC on MCP calls.
	ProviderMCPEndUserPermission = "mcp_end_user_permission"
)

type mcpServerReference struct {
	ServerID    string
	ServerLabel string
	ServerURL   string
	Source      string
}

// MCPSecurityDriver validates MCP server references in LLM tool declarations and pre_mcp_call
// payloads against registered tenant MCPServer entries and explicit allowlists, with optional SSRF checks.
type MCPSecurityDriver struct {
	guardrailName       string
	action              string // "block" or "flag"
	repo                storage.Repository
	allowTenantRegistry bool
	requireRegistered   bool
	allowedServerURLs   []string
	allowedServerLabels []string
	blockedServerURLs   []string
	blockedServerLabels []string
	enforceSSRF         bool
	resolveDNS          bool
	netPolicy           *network.Policy
}

// NewMCPSecurityDriver constructs an MCPSecurityDriver from resolved guardrail config and optional repository.
func NewMCPSecurityDriver(cfg guardrails.DriverConfig, repos ...storage.Repository) (*MCPSecurityDriver, error) {
	action, err := resolveDriverAction(cfg, "block", false)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", ProviderMCPSecurity, err)
	}

	var repo storage.Repository
	if len(repos) > 0 {
		repo = repos[0]
	}

	rawCfg := cfg.EffectiveConfig
	d := &MCPSecurityDriver{
		guardrailName:       definitionName(cfg, ProviderMCPSecurity),
		action:              action,
		repo:                repo,
		allowTenantRegistry: boolFromAny(rawCfg["allow_tenant_registry"], true),
		requireRegistered:   boolFromAny(rawCfg["require_registered_server"], false),
		allowedServerURLs:   normalizeLowerStrings(stringSliceFromAny(rawCfg["allowed_server_urls"])),
		allowedServerLabels: normalizeLowerStrings(collectMultiStringSlices(rawCfg, "allowed_server_labels", "allowed_servers", "allowed_server_slugs")),
		blockedServerURLs:   normalizeLowerStrings(stringSliceFromAny(rawCfg["blocked_server_urls"])),
		blockedServerLabels: normalizeLowerStrings(collectMultiStringSlices(rawCfg, "blocked_server_labels", "blocked_servers", "blocked_server_slugs")),
		enforceSSRF:         boolFromAny(rawCfg["enforce_ssrf"], false),
		resolveDNS:          boolFromAny(rawCfg["resolve_dns"], false),
	}

	if d.enforceSSRF {
		schemes := stringSliceFromAny(rawCfg["allowed_schemes"])
		if len(schemes) == 0 && !boolFromAny(rawCfg["allow_insecure_http"], false) {
			schemes = []string{"https"}
		}
		pol, err := network.NewPolicy(config.OutboundSSRFConfig{
			AllowPrivateNetworks: boolFromAny(rawCfg["allow_private_networks"], false),
			AllowInsecureHTTP:    boolFromAny(rawCfg["allow_insecure_http"], false),
			AllowedSchemes:       schemes,
		})
		if err != nil {
			return nil, fmt.Errorf("%s: build SSRF policy: %w", ProviderMCPSecurity, err)
		}
		d.netPolicy = pol
	}

	return d, nil
}

// Name returns the provider identifier for MCPSecurityDriver.
func (d *MCPSecurityDriver) Name() string {
	return ProviderMCPSecurity
}

// SupportedHooks returns the lifecycle hooks evaluated by MCPSecurityDriver.
func (d *MCPSecurityDriver) SupportedHooks() []domain.GuardrailHook {
	return []domain.GuardrailHook{
		domain.GuardrailHookPreCall,
		domain.GuardrailHookPreMCPCall,
	}
}

// Evaluate validates MCP server declarations and pre_mcp_call server references.
func (d *MCPSecurityDriver) Evaluate(ctx context.Context, input *domain.GuardrailEvalInput) (*domain.GuardrailEvalResult, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if input == nil {
		return &domain.GuardrailEvalResult{Decision: domain.GuardrailDecisionAllow}, nil
	}

	refs := extractMCPServerReferences(input)
	if len(refs) == 0 {
		return &domain.GuardrailEvalResult{
			Decision:          domain.GuardrailDecisionAllow,
			AppliedGuardrails: []string{d.guardrailName},
		}, nil
	}

	var registeredServers []*domain.MCPServer
	if d.repo != nil && d.allowTenantRegistry && strings.TrimSpace(input.OrgID) != "" {
		servers, err := d.repo.ListMCPServers(ctx, input.OrgID)
		if err != nil {
			return nil, fmt.Errorf("%s: list tenant mcp servers: %w", ProviderMCPSecurity, err)
		}
		registeredServers = servers
	}

	var violations []domain.GuardrailViolation
	for _, ref := range refs {
		if v := d.validateReference(ctx, ref, registeredServers); v != nil {
			violations = append(violations, *v)
		}
	}

	if len(violations) == 0 {
		return &domain.GuardrailEvalResult{
			Decision:          domain.GuardrailDecisionAllow,
			AppliedGuardrails: []string{d.guardrailName},
		}, nil
	}

	if d.action == "flag" {
		return &domain.GuardrailEvalResult{
			Decision:          domain.GuardrailDecisionFlag,
			Violations:        violations,
			AppliedGuardrails: []string{d.guardrailName},
		}, nil
	}

	return &domain.GuardrailEvalResult{
		Decision:          domain.GuardrailDecisionBlock,
		Violations:        violations,
		AppliedGuardrails: []string{d.guardrailName},
		ErrorMessage:      violations[0].Message,
	}, nil
}

func (d *MCPSecurityDriver) validateReference(ctx context.Context, ref mcpServerReference, registered []*domain.MCPServer) *domain.GuardrailViolation {
	normURL := normalizeMCPURL(ref.ServerURL)
	normLabel := strings.ToLower(strings.TrimSpace(ref.ServerLabel))
	normID := strings.ToLower(strings.TrimSpace(ref.ServerID))

	// 1. Explicit denylist checks.
	if normURL != "" {
		for _, blocked := range d.blockedServerURLs {
			if matchURLOrGlob(blocked, normURL) {
				return d.newViolation("blocked_mcp_server",
					fmt.Sprintf("MCP server URL %q is explicitly blocked by policy", ref.ServerURL),
					ref,
				)
			}
		}
	}
	if normLabel != "" {
		for _, blocked := range d.blockedServerLabels {
			if matchGlobPattern(blocked, normLabel) {
				return d.newViolation("blocked_mcp_server",
					fmt.Sprintf("MCP server %q is explicitly blocked by policy", ref.ServerLabel),
					ref,
				)
			}
		}
	}

	// 2. Optional SSRF and scheme enforcement on server URL.
	if normURL != "" {
		parsed, err := url.Parse(strings.TrimSpace(ref.ServerURL))
		if err != nil || parsed.Scheme == "" || parsed.Hostname() == "" {
			return d.newViolation("invalid_mcp_server_url",
				fmt.Sprintf("MCP server URL %q is malformed", ref.ServerURL),
				ref,
			)
		}
		if d.enforceSSRF && d.netPolicy != nil {
			if err := d.netPolicy.ValidateURL(parsed); err != nil {
				return d.newViolation("mcp_ssrf_blocked",
					fmt.Sprintf("MCP server URL %q rejected by network security policy: %v", ref.ServerURL, err),
					ref,
				)
			}
			if d.resolveDNS && net.ParseIP(parsed.Hostname()) == nil {
				ips, err := net.DefaultResolver.LookupIPAddr(ctx, parsed.Hostname())
				if err != nil {
					return d.newViolation("mcp_ssrf_blocked",
						fmt.Sprintf("MCP server URL %q failed DNS resolution: %v", ref.ServerURL, err),
						ref,
					)
				}
				for _, ipAddr := range ips {
					if err := d.netPolicy.ValidateIP(ipAddr.IP); err != nil {
						return d.newViolation("mcp_ssrf_blocked",
							fmt.Sprintf("MCP server URL %q resolved to forbidden IP: %v", ref.ServerURL, err),
							ref,
						)
					}
				}
			}
		}
	}

	// 3. Match against active tenant MCPServer registry entries.
	var matchedByLabel *domain.MCPServer
	var matchedByURL *domain.MCPServer
	for _, srv := range registered {
		if srv == nil || !srv.IsActive {
			continue
		}
		srvURL := normalizeMCPURL(srv.EndpointURL)
		srvSlug := strings.ToLower(strings.TrimSpace(srv.Slug))
		srvName := strings.ToLower(strings.TrimSpace(srv.Name))
		srvID := strings.ToLower(strings.TrimSpace(srv.ID))

		if normURL != "" && srvURL != "" && srvURL == normURL {
			matchedByURL = srv
		}
		if (normLabel != "" && (normLabel == srvSlug || normLabel == srvName)) || (normID != "" && normID == srvID) {
			matchedByLabel = srv
		}
	}

	// Anti-spoofing: if label identifies a registered server and a different URL was supplied, reject.
	if matchedByLabel != nil && normURL != "" && normalizeMCPURL(matchedByLabel.EndpointURL) != normURL {
		return d.newViolation("mcp_server_url_mismatch",
			fmt.Sprintf("MCP server %q URL %q does not match registered endpoint", ref.ServerLabel, ref.ServerURL),
			ref,
		)
	}

	if normURL != "" {
		if matchedByURL != nil {
			return nil
		}
		if !d.requireRegistered && d.isExplicitlyAllowedURL(normURL) {
			return nil
		}
		return d.newViolation("untrusted_mcp_server",
			fmt.Sprintf("MCP server URL %q is not a registered or allowlisted MCP server", ref.ServerURL),
			ref,
		)
	}

	if normLabel != "" || normID != "" {
		if matchedByLabel != nil {
			return nil
		}
		if !d.requireRegistered && normLabel != "" && d.isExplicitlyAllowedLabel(normLabel) {
			return nil
		}
		label := ref.ServerLabel
		if label == "" {
			label = ref.ServerID
		}
		return d.newViolation("untrusted_mcp_server",
			fmt.Sprintf("MCP server %q is not a registered or allowlisted MCP server", label),
			ref,
		)
	}

	return nil
}

func (d *MCPSecurityDriver) isExplicitlyAllowedURL(normURL string) bool {
	for _, allowed := range d.allowedServerURLs {
		if matchURLOrGlob(allowed, normURL) {
			return true
		}
	}
	return false
}

func (d *MCPSecurityDriver) isExplicitlyAllowedLabel(normLabel string) bool {
	for _, allowed := range d.allowedServerLabels {
		if matchGlobPattern(allowed, normLabel) {
			return true
		}
	}
	return false
}

func (d *MCPSecurityDriver) newViolation(rule, msg string, ref mcpServerReference) *domain.GuardrailViolation {
	action := domain.GuardrailActionBlock
	if d.action == "flag" {
		action = domain.GuardrailActionAudit
	}
	return &domain.GuardrailViolation{
		GuardrailName: d.guardrailName,
		Provider:      ProviderMCPSecurity,
		Category:      "mcp_security",
		Rule:          rule,
		Severity:      "high",
		Message:       msg,
		Action:        action,
		Details: map[string]any{
			"server_id":    ref.ServerID,
			"server_label": ref.ServerLabel,
			"server_url":   ref.ServerURL,
			"source":       ref.Source,
		},
	}
}

func extractMCPServerReferences(input *domain.GuardrailEvalInput) []mcpServerReference {
	var refs []mcpServerReference
	seen := make(map[string]struct{})
	addRef := func(ref mcpServerReference) {
		ref.ServerID = strings.TrimSpace(ref.ServerID)
		ref.ServerLabel = strings.TrimSpace(ref.ServerLabel)
		ref.ServerURL = strings.TrimSpace(ref.ServerURL)
		if ref.ServerID == "" && ref.ServerLabel == "" && ref.ServerURL == "" {
			return
		}
		key := strings.ToLower(ref.ServerID + "|" + ref.ServerLabel + "|" + normalizeMCPURL(ref.ServerURL))
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		refs = append(refs, ref)
	}

	for _, tool := range input.Tools {
		isMCP := strings.EqualFold(strings.TrimSpace(tool.Type), "mcp")
		params := tool.Function.Parameters
		if !isMCP && params != nil {
			if t, ok := params["type"].(string); ok && strings.EqualFold(strings.TrimSpace(t), "mcp") {
				isMCP = true
			}
			if extractStringFromMetadata(params, "server_url", "endpoint_url") != "" {
				isMCP = true
			}
		}
		if !isMCP {
			continue
		}
		serverURL := extractStringFromMetadata(params, "server_url", "endpoint_url", "url")
		serverLabel := extractStringFromMetadata(params, "server_label", "server_slug", "slug", "label")
		if serverLabel == "" {
			serverLabel = tool.Function.Name
		}
		serverID := extractStringFromMetadata(params, "server_id", "mcp_server_id")
		addRef(mcpServerReference{
			ServerID:    serverID,
			ServerLabel: serverLabel,
			ServerURL:   serverURL,
			Source:      "tools",
		})
	}

	if len(input.Metadata) > 0 {
		addRef(mcpServerReference{
			ServerID:    extractStringFromMetadata(input.Metadata, "mcp_server_id", "server_id"),
			ServerLabel: extractStringFromMetadata(input.Metadata, "mcp_server_slug", "server_label", "server_slug"),
			ServerURL:   extractStringFromMetadata(input.Metadata, "mcp_server_url", "server_url", "endpoint_url"),
			Source:      "metadata",
		})

		for _, listKey := range []string{"tools", "mcp_tools", "mcp_servers"} {
			rawList, ok := input.Metadata[listKey]
			if !ok {
				continue
			}
			for _, item := range mapSliceFromAny(rawList) {
				typ := extractStringFromMetadata(item, "type")
				sURL := extractStringFromMetadata(item, "server_url", "endpoint_url", "url")
				sLabel := extractStringFromMetadata(item, "server_label", "server_slug", "slug", "label", "name")
				sID := extractStringFromMetadata(item, "server_id", "mcp_server_id", "id")
				if strings.EqualFold(typ, "mcp") || listKey != "tools" || sURL != "" {
					addRef(mcpServerReference{
						ServerID:    sID,
						ServerLabel: sLabel,
						ServerURL:   sURL,
						Source:      "metadata." + listKey,
					})
				}
			}
		}
	}

	return refs
}

func normalizeMCPURL(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ""
	}
	u, err := url.Parse(trimmed)
	if err != nil {
		return strings.ToLower(strings.TrimRight(trimmed, "/"))
	}
	u.Scheme = strings.ToLower(u.Scheme)
	u.Host = strings.ToLower(u.Host)
	u.Path = strings.TrimRight(u.Path, "/")
	u.Fragment = ""
	return u.String()
}

func matchURLOrGlob(pattern, target string) bool {
	normPattern := normalizeMCPURL(pattern)
	if normPattern == "*" {
		return true
	}
	if strings.HasSuffix(normPattern, "*") {
		prefix := strings.TrimSuffix(normPattern, "*")
		return strings.HasPrefix(target, prefix)
	}
	if strings.ContainsAny(normPattern, "*?[") {
		return matchGlobPattern(normPattern, target)
	}
	return normPattern == target
}

type mcpPermissionRule struct {
	Servers        []string
	Tools          []string
	Effect         string // "allow" or "deny"
	AllowedUsers   []string
	DeniedUsers    []string
	AllowedRoles   []string
	AllowedTeams   []string
	RequiredClaims map[string]any
}

// MCPEndUserPermissionDriver validates caller EndUserID, OIDC claims, caller roles, and team RBAC
// against ordered per-server/per-tool permission rules before MCP tool dispatch.
type MCPEndUserPermissionDriver struct {
	guardrailName string
	action        string // "block" or "flag"
	defaultAction string // "allow" or "deny"
	rules         []mcpPermissionRule
}

// NewMCPEndUserPermissionDriver constructs an MCPEndUserPermissionDriver from resolved config.
func NewMCPEndUserPermissionDriver(cfg guardrails.DriverConfig) (*MCPEndUserPermissionDriver, error) {
	action, err := resolveDriverAction(cfg, "block", false)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", ProviderMCPEndUserPermission, err)
	}

	rawCfg := cfg.EffectiveConfig
	rules, err := parseMCPPermissionRules(rawCfg)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", ProviderMCPEndUserPermission, err)
	}

	defaultAct := strings.ToLower(strings.TrimSpace(stringFromAny(rawCfg["default_action"])))
	switch defaultAct {
	case "":
		if len(rules) > 0 {
			defaultAct = "deny"
		} else {
			defaultAct = "allow"
		}
	case "allow", "permit":
		defaultAct = "allow"
	case "deny", "block":
		defaultAct = "deny"
	default:
		return nil, fmt.Errorf("%s: invalid default_action %q", ProviderMCPEndUserPermission, defaultAct)
	}

	return &MCPEndUserPermissionDriver{
		guardrailName: definitionName(cfg, ProviderMCPEndUserPermission),
		action:        action,
		defaultAction: defaultAct,
		rules:         rules,
	}, nil
}

// Name returns the provider identifier for MCPEndUserPermissionDriver.
func (d *MCPEndUserPermissionDriver) Name() string {
	return ProviderMCPEndUserPermission
}

// SupportedHooks returns the lifecycle hooks evaluated by MCPEndUserPermissionDriver.
func (d *MCPEndUserPermissionDriver) SupportedHooks() []domain.GuardrailHook {
	return []domain.GuardrailHook{
		domain.GuardrailHookPreMCPCall,
		domain.GuardrailHookPreCall,
	}
}

// Evaluate validates caller end-user identity, roles, team, and OIDC claims per MCP server and tool.
func (d *MCPEndUserPermissionDriver) Evaluate(ctx context.Context, input *domain.GuardrailEvalInput) (*domain.GuardrailEvalResult, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if input == nil || len(d.rules) == 0 {
		return &domain.GuardrailEvalResult{
			Decision:          domain.GuardrailDecisionAllow,
			AppliedGuardrails: []string{d.guardrailName},
		}, nil
	}

	targets := extractMCPInvocationTargets(input)
	if len(targets) == 0 {
		return &domain.GuardrailEvalResult{
			Decision:          domain.GuardrailDecisionAllow,
			AppliedGuardrails: []string{d.guardrailName},
		}, nil
	}

	endUserID := strings.TrimSpace(input.EndUserID)
	if endUserID == "" {
		endUserID = extractStringFromMetadata(input.Metadata, "end_user_id", "user_id")
	}
	teamID := strings.TrimSpace(input.TeamID)
	oidcClaims := extractOIDCClaims(input.Metadata)
	callerRoles := extractCallerRoles(input.Metadata, oidcClaims)

	var violations []domain.GuardrailViolation
	for _, target := range targets {
		if reason, ruleName := d.authorizeTarget(target.Server, target.Tool, endUserID, teamID, callerRoles, oidcClaims); reason != "" {
			vAction := domain.GuardrailActionBlock
			if d.action == "flag" {
				vAction = domain.GuardrailActionAudit
			}
			violations = append(violations, domain.GuardrailViolation{
				GuardrailName: d.guardrailName,
				Provider:      ProviderMCPEndUserPermission,
				Category:      "mcp_end_user_permission",
				Rule:          ruleName,
				Severity:      "high",
				Message:       reason,
				Action:        vAction,
				Details: map[string]any{
					"server":      target.Server,
					"tool":        target.Tool,
					"end_user_id": endUserID,
					"team_id":     teamID,
				},
			})
		}
	}

	if len(violations) == 0 {
		return &domain.GuardrailEvalResult{
			Decision:          domain.GuardrailDecisionAllow,
			AppliedGuardrails: []string{d.guardrailName},
		}, nil
	}

	if d.action == "flag" {
		return &domain.GuardrailEvalResult{
			Decision:          domain.GuardrailDecisionFlag,
			Violations:        violations,
			AppliedGuardrails: []string{d.guardrailName},
		}, nil
	}

	return &domain.GuardrailEvalResult{
		Decision:          domain.GuardrailDecisionBlock,
		Violations:        violations,
		AppliedGuardrails: []string{d.guardrailName},
		ErrorMessage:      violations[0].Message,
	}, nil
}

func (d *MCPEndUserPermissionDriver) authorizeTarget(
	server, tool, endUserID, teamID string,
	callerRoles []string,
	oidcClaims map[string]any,
) (string, string) {
	normServer := strings.ToLower(strings.TrimSpace(server))
	normTool := strings.ToLower(strings.TrimSpace(tool))

	for _, rule := range d.rules {
		if !matchesAnyPattern(rule.Servers, normServer) || !matchesAnyPattern(rule.Tools, normTool) {
			continue
		}

		if rule.Effect == "deny" {
			return fmt.Sprintf("Caller %q is denied access to MCP tool %s/%s", endUserID, server, tool), "explicit_deny"
		}

		if len(rule.DeniedUsers) > 0 && endUserID != "" && matchesAnyPattern(rule.DeniedUsers, strings.ToLower(endUserID)) {
			return fmt.Sprintf("End user %q is explicitly denied MCP tool %s/%s", endUserID, server, tool), "denied_user"
		}
		if len(rule.AllowedUsers) > 0 {
			if endUserID == "" || !matchesAnyPattern(rule.AllowedUsers, strings.ToLower(endUserID)) {
				return fmt.Sprintf("End user %q is not authorized for MCP tool %s/%s", endUserID, server, tool), "end_user_not_allowed"
			}
		}
		if len(rule.AllowedTeams) > 0 {
			if teamID == "" || !matchesAnyPattern(rule.AllowedTeams, strings.ToLower(teamID)) {
				return fmt.Sprintf("Team %q is not authorized for MCP tool %s/%s", teamID, server, tool), "team_not_allowed"
			}
		}
		if len(rule.AllowedRoles) > 0 {
			if !hasAnyMatchingRole(rule.AllowedRoles, callerRoles) {
				return fmt.Sprintf("Caller lacks required role for MCP tool %s/%s", server, tool), "role_not_allowed"
			}
		}
		if len(rule.RequiredClaims) > 0 {
			if missingReason := validateRequiredOIDCClaims(rule.RequiredClaims, oidcClaims); missingReason != "" {
				return fmt.Sprintf("Caller failed OIDC claim policy for MCP tool %s/%s: %s", server, tool, missingReason), "oidc_claim_denied"
			}
		}
		return "", ""
	}

	if d.defaultAction == "deny" {
		return fmt.Sprintf("No permission rule allows MCP tool %s/%s (default deny)", server, tool), "default_deny"
	}
	return "", ""
}

type mcpInvocationTarget struct {
	Server string
	Tool   string
}

func extractMCPInvocationTargets(input *domain.GuardrailEvalInput) []mcpInvocationTarget {
	server := extractStringFromMetadata(input.Metadata, "mcp_server_slug", "server_slug", "server_label", "mcp_server_id")

	var targets []mcpInvocationTarget
	for _, tc := range input.ToolCalls {
		if input.Hook != domain.GuardrailHookPreMCPCall && !strings.EqualFold(tc.Type, "mcp") && server == "" {
			continue
		}
		if strings.TrimSpace(tc.Function.Name) != "" {
			targets = append(targets, mcpInvocationTarget{
				Server: server,
				Tool:   strings.TrimSpace(tc.Function.Name),
			})
		}
	}

	if len(targets) == 0 {
		if metaTool := extractStringFromMetadata(input.Metadata, "mcp_tool_name", "tool_name"); metaTool != "" {
			targets = append(targets, mcpInvocationTarget{
				Server: server,
				Tool:   metaTool,
			})
		}
	}
	return targets
}

func parseMCPPermissionRules(rawCfg map[string]any) ([]mcpPermissionRule, error) {
	if len(rawCfg) == 0 {
		return nil, nil
	}

	var rules []mcpPermissionRule
	for _, rawRule := range mapSliceFromAny(rawCfg["rules"]) {
		rule, err := parseSingleMCPPermissionRule(rawRule)
		if err != nil {
			return nil, err
		}
		rules = append(rules, rule)
	}

	// Support top-level flat allowlist keys as a single rule when rules[] is omitted
	// or as an additional global constraint when top-level keys are explicitly set.
	if hasTopLevelPermissionKeys(rawCfg) {
		topRule, err := parseSingleMCPPermissionRule(rawCfg)
		if err != nil {
			return nil, err
		}
		if len(rules) == 0 {
			rules = append(rules, topRule)
		}
	}
	return rules, nil
}

func hasTopLevelPermissionKeys(rawCfg map[string]any) bool {
	for _, k := range []string{"allowed_users", "denied_users", "allowed_roles", "required_roles", "allowed_teams", "required_teams", "required_claims"} {
		if _, ok := rawCfg[k]; ok {
			return true
		}
	}
	return false
}

func parseSingleMCPPermissionRule(m map[string]any) (mcpPermissionRule, error) {
	servers := normalizeLowerStrings(collectMultiStringSlices(m, "servers", "server", "server_pattern", "server_slug"))
	if len(servers) == 0 {
		servers = []string{"*"}
	}
	tools := normalizeLowerStrings(collectMultiStringSlices(m, "tools", "tool", "tool_pattern", "tool_name"))
	if len(tools) == 0 {
		tools = []string{"*"}
	}

	effect := strings.ToLower(strings.TrimSpace(stringFromAny(m["effect"])))
	if effect == "" {
		effect = strings.ToLower(strings.TrimSpace(stringFromAny(m["action"])))
	}
	switch effect {
	case "", "allow", "permit":
		effect = "allow"
	case "deny", "block":
		effect = "deny"
	default:
		return mcpPermissionRule{}, fmt.Errorf("invalid rule effect %q", effect)
	}

	var requiredClaims map[string]any
	if rawClaims, ok := m["required_claims"]; ok && rawClaims != nil {
		switch typed := rawClaims.(type) {
		case map[string]any:
			requiredClaims = typed
		case map[string]string:
			requiredClaims = make(map[string]any, len(typed))
			for k, v := range typed {
				requiredClaims[k] = v
			}
		case []string:
			requiredClaims = make(map[string]any, len(typed))
			for _, k := range typed {
				requiredClaims[k] = true
			}
		case []any:
			requiredClaims = make(map[string]any, len(typed))
			for _, item := range typed {
				if s, ok := item.(string); ok && strings.TrimSpace(s) != "" {
					requiredClaims[strings.TrimSpace(s)] = true
				}
			}
		default:
			return mcpPermissionRule{}, fmt.Errorf("invalid required_claims type %T", rawClaims)
		}
	}

	return mcpPermissionRule{
		Servers:        servers,
		Tools:          tools,
		Effect:         effect,
		AllowedUsers:   normalizeLowerStrings(stringSliceFromAny(m["allowed_users"])),
		DeniedUsers:    normalizeLowerStrings(stringSliceFromAny(m["denied_users"])),
		AllowedRoles:   normalizeLowerStrings(collectMultiStringSlices(m, "allowed_roles", "required_roles")),
		AllowedTeams:   normalizeLowerStrings(collectMultiStringSlices(m, "allowed_teams", "required_teams")),
		RequiredClaims: requiredClaims,
	}, nil
}

func extractOIDCClaims(meta map[string]any) map[string]any {
	if len(meta) == 0 {
		return nil
	}
	raw, ok := meta["oidc_claims"]
	if !ok || raw == nil {
		return nil
	}
	switch typed := raw.(type) {
	case map[string]any:
		return typed
	case map[string]string:
		out := make(map[string]any, len(typed))
		for k, v := range typed {
			out[k] = v
		}
		return out
	case string:
		var decoded map[string]any
		if err := json.Unmarshal([]byte(typed), &decoded); err == nil {
			return decoded
		}
	}
	return nil
}

func extractCallerRoles(meta, oidcClaims map[string]any) []string {
	var roles []string
	seen := make(map[string]struct{})
	add := func(r string) {
		norm := strings.ToLower(strings.TrimSpace(r))
		if norm == "" {
			return
		}
		if _, ok := seen[norm]; !ok {
			seen[norm] = struct{}{}
			roles = append(roles, norm)
		}
	}
	for _, r := range stringSliceFromAny(meta["caller_roles"]) {
		add(r)
	}
	for _, r := range stringSliceFromAny(meta["roles"]) {
		add(r)
	}
	if len(oidcClaims) > 0 {
		for _, r := range stringSliceFromAny(oidcClaims["roles"]) {
			add(r)
		}
		for _, r := range stringSliceFromAny(oidcClaims["role"]) {
			add(r)
		}
		for _, r := range stringSliceFromAny(oidcClaims["groups"]) {
			add(r)
		}
	}
	return roles
}

func hasAnyMatchingRole(allowedRoles, callerRoles []string) bool {
	for _, allowed := range allowedRoles {
		if allowed == "*" {
			return len(callerRoles) > 0
		}
		for _, actual := range callerRoles {
			if matchGlobPattern(allowed, actual) {
				return true
			}
		}
	}
	return false
}

func validateRequiredOIDCClaims(required, actual map[string]any) string {
	for claimKey, want := range required {
		got, exists := actual[claimKey]
		if !exists || got == nil {
			return fmt.Sprintf("missing claim %q", claimKey)
		}
		if !claimMatchesExpectation(claimKey, want, got) {
			return fmt.Sprintf("claim %q mismatch", claimKey)
		}
	}
	return ""
}

func claimMatchesExpectation(claimKey string, want, got any) bool {
	if b, ok := want.(bool); ok && b {
		switch g := got.(type) {
		case string:
			return strings.TrimSpace(g) != ""
		case []string:
			return len(g) > 0
		case []any:
			return len(g) > 0
		case bool:
			return g
		default:
			return got != nil
		}
	}

	// If want is a slice of acceptable values, match if got matches any element.
	if wantSlice := stringSliceFromAny(want); len(wantSlice) > 0 {
		if _, isSlice := want.([]string); isSlice {
			return matchesAnyClaimValue(claimKey, wantSlice, got)
		}
		if _, isAnySlice := want.([]any); isAnySlice {
			return matchesAnyClaimValue(claimKey, wantSlice, got)
		}
	}

	if wantStr, ok := want.(string); ok {
		return matchesAnyClaimValue(claimKey, []string{wantStr}, got)
	}

	return fmt.Sprint(want) == fmt.Sprint(got)
}

func matchesAnyClaimValue(claimKey string, accepted []string, got any) bool {
	gotSlice := stringSliceFromAny(got)
	if len(gotSlice) == 1 && (claimKey == "scope" || claimKey == "scp") && strings.Contains(gotSlice[0], " ") {
		gotSlice = strings.Fields(gotSlice[0])
	}
	for _, w := range accepted {
		for _, g := range gotSlice {
			if g == w {
				return true
			}
		}
	}
	return false
}

func matchesAnyPattern(patterns []string, value string) bool {
	for _, p := range patterns {
		if matchGlobPattern(p, value) {
			return true
		}
	}
	return false
}

func collectMultiStringSlices(m map[string]any, keys ...string) []string {
	var out []string
	for _, k := range keys {
		out = append(out, stringSliceFromAny(m[k])...)
	}
	return out
}

func normalizeLowerStrings(items []string) []string {
	if len(items) == 0 {
		return nil
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		norm := strings.ToLower(strings.TrimSpace(item))
		if norm != "" {
			out = append(out, norm)
		}
	}
	return out
}

func stringFromAny(v any) string {
	s, _ := v.(string)
	return s
}

func mapSliceFromAny(v any) []map[string]any {
	switch typed := v.(type) {
	case []map[string]any:
		return typed
	case []any:
		out := make([]map[string]any, 0, len(typed))
		for _, item := range typed {
			if m, ok := item.(map[string]any); ok {
				out = append(out, m)
			}
		}
		return out
	}
	return nil
}
