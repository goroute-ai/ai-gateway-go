package auth

import (
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
)

// Strict identity-only target attributes permitted in ProxyAuthConfig.HeaderMapping.
// Privileged authorization attributes (role, budget, rpm, tpm, permissions, allowed_models)
// are never permitted from reverse-proxy headers.
const (
	ProxyAttrUserID    = "user_id"
	ProxyAttrUserEmail = "user_email"
	ProxyAttrTeamID    = "team_id"
	ProxyAttrOrgID     = "org_id"
)

// ProxyAuthConfig configures CIDR-guarded reverse-proxy identity header authentication.
type ProxyAuthConfig struct {
	Enabled           bool              `yaml:"enabled" json:"enabled"`
	TrustedProxyCIDRs []string          `yaml:"trusted_proxy_cidrs" json:"trusted_proxy_cidrs"`
	HeaderMapping     map[string]string `yaml:"header_mapping" json:"header_mapping"`
}

// ProxyIdentity contains the validated identity-only attributes extracted from a trusted reverse proxy.
// Privileged authorization fields (role, budgets, rate limits, permissions, allowed models) are
// intentionally absent and must always be resolved server-side from persistent tenant records.
type ProxyIdentity struct {
	UserID    string `json:"user_id,omitempty"`
	UserEmail string `json:"user_email,omitempty"`
	TeamID    string `json:"team_id,omitempty"`
	OrgID     string `json:"org_id,omitempty"`
	SourceIP  string `json:"source_ip,omitempty"`
}

// DefaultProxyHeaderMapping returns the standard reverse-proxy identity header mapping.
func DefaultProxyHeaderMapping() map[string]string {
	return map[string]string{
		"X-Auth-Request-User":  ProxyAttrUserID,
		"X-Auth-Request-Email": ProxyAttrUserEmail,
		"X-Auth-Request-Team":  ProxyAttrTeamID,
		"X-Auth-Request-Org":   ProxyAttrOrgID,
	}
}

// IsAllowedProxyAttribute reports whether attr is on the strict identity-only allowlist.
func IsAllowedProxyAttribute(attr string) bool {
	switch normalizeProxyAttr(attr) {
	case ProxyAttrUserID, ProxyAttrUserEmail, ProxyAttrTeamID, ProxyAttrOrgID:
		return true
	default:
		return false
	}
}

func normalizeProxyAttr(attr string) string {
	return strings.ToLower(strings.TrimSpace(attr))
}

// Validate checks that TrustedProxyCIDRs are valid CIDR expressions and that every entry in
// HeaderMapping targets only the strict identity-only allowlist.
func (c ProxyAuthConfig) Validate() error {
	for _, rawCIDR := range c.TrustedProxyCIDRs {
		trimmed := strings.TrimSpace(rawCIDR)
		if trimmed == "" {
			return fmt.Errorf("trusted_proxy_cidrs must not contain empty entries")
		}
		if _, _, err := net.ParseCIDR(trimmed); err != nil {
			return fmt.Errorf("invalid trusted_proxy_cidrs entry %q: %w", rawCIDR, err)
		}
	}

	seenHeaders := make(map[string]string, len(c.HeaderMapping))
	for rawHeader, rawTarget := range c.HeaderMapping {
		headerName := strings.TrimSpace(rawHeader)
		if headerName == "" {
			return fmt.Errorf("header_mapping must not contain empty header names")
		}
		canonicalHeader := http.CanonicalHeaderKey(headerName)
		target := normalizeProxyAttr(rawTarget)
		if !IsAllowedProxyAttribute(target) {
			return fmt.Errorf("header_mapping target %q for header %q is not in the identity-only allowlist (allowed: user_id, user_email, team_id, org_id)", rawTarget, rawHeader)
		}
		if prev, exists := seenHeaders[canonicalHeader]; exists && prev != target {
			return fmt.Errorf("conflicting header_mapping entries for canonical header %q (%q vs %q)", canonicalHeader, prev, target)
		}
		seenHeaders[canonicalHeader] = target
	}

	return nil
}

// ProxyAuthenticator verifies raw socket source IPs against TrustedProxyCIDRs and extracts
// allowlisted identity attributes from configured reverse-proxy headers.
type ProxyAuthenticator struct {
	enabled       bool
	trustedNets   []*net.IPNet
	headerMapping map[string]string // canonical header name -> normalized allowlisted attribute
}

// NewProxyAuthenticator validates cfg and constructs a fail-closed ProxyAuthenticator.
func NewProxyAuthenticator(cfg ProxyAuthConfig) (*ProxyAuthenticator, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	nets := make([]*net.IPNet, 0, len(cfg.TrustedProxyCIDRs))
	for _, rawCIDR := range cfg.TrustedProxyCIDRs {
		_, ipNet, err := net.ParseCIDR(strings.TrimSpace(rawCIDR))
		if err != nil {
			return nil, fmt.Errorf("parse CIDR %q: %w", rawCIDR, err)
		}
		nets = append(nets, ipNet)
	}

	mapping := make(map[string]string, len(cfg.HeaderMapping))
	for rawHeader, rawTarget := range cfg.HeaderMapping {
		canonicalHeader := http.CanonicalHeaderKey(strings.TrimSpace(rawHeader))
		mapping[canonicalHeader] = normalizeProxyAttr(rawTarget)
	}

	return &ProxyAuthenticator{
		enabled:       cfg.Enabled,
		trustedNets:   nets,
		headerMapping: mapping,
	}, nil
}

// Enabled reports whether reverse-proxy header authentication is enabled.
func (p *ProxyAuthenticator) Enabled() bool {
	return p != nil && p.enabled
}

// IsTrustedSource checks whether the raw socket address (r.RemoteAddr) belongs to TrustedProxyCIDRs.
// It fails closed when TrustedProxyCIDRs is empty or the address is invalid.
func (p *ProxyAuthenticator) IsTrustedSource(remoteAddr string) bool {
	if p == nil || len(p.trustedNets) == 0 {
		return false
	}
	return p.isIPInTrustedNets(extractRawSocketIP(remoteAddr))
}

// Authenticate validates the raw socket IP (r.RemoteAddr) against TrustedProxyCIDRs and extracts
// identity-only attributes from configured reverse-proxy headers.
// Forwarded IP headers (such as X-Forwarded-For or X-Real-IP) are never consulted for trust decisions.
func (p *ProxyAuthenticator) Authenticate(r *http.Request) (*ProxyIdentity, error) {
	if p == nil || !p.enabled {
		return nil, &domain.GatewayError{
			StatusCode: http.StatusUnauthorized,
			Type:       domain.ErrorTypeAuthentication,
			Code:       "proxy_auth_disabled",
			Message:    "Reverse-proxy authentication is not enabled",
		}
	}
	if r == nil {
		return nil, &domain.GatewayError{
			StatusCode: http.StatusUnauthorized,
			Type:       domain.ErrorTypeAuthentication,
			Code:       "invalid_proxy_request",
			Message:    "HTTP request is required for proxy authentication",
		}
	}
	if len(p.trustedNets) == 0 {
		return nil, &domain.GatewayError{
			StatusCode: http.StatusForbidden,
			Type:       domain.ErrorTypePermission,
			Code:       "untrusted_proxy",
			Message:    "Trusted proxy CIDRs are not configured",
		}
	}

	remoteIP := extractRawSocketIP(r.RemoteAddr)
	if remoteIP == nil || !p.isIPInTrustedNets(remoteIP) {
		return nil, &domain.GatewayError{
			StatusCode: http.StatusForbidden,
			Type:       domain.ErrorTypePermission,
			Code:       "untrusted_proxy",
			Message:    "Request source IP is not in trusted_proxy_cidrs",
		}
	}

	identity := &ProxyIdentity{
		SourceIP: remoteIP.String(),
	}

	for headerName, attr := range p.headerMapping {
		val, err := readSingleProxyHeader(r.Header, headerName)
		if err != nil {
			return nil, err
		}
		if val == "" {
			continue
		}

		switch attr {
		case ProxyAttrUserID:
			identity.UserID = val
		case ProxyAttrUserEmail:
			identity.UserEmail = val
		case ProxyAttrTeamID:
			identity.TeamID = val
		case ProxyAttrOrgID:
			identity.OrgID = val
		default:
			return nil, &domain.GatewayError{
				StatusCode: http.StatusForbidden,
				Type:       domain.ErrorTypePermission,
				Code:       "disallowed_proxy_attribute",
				Message:    fmt.Sprintf("Proxy attribute %q is not permitted", attr),
			}
		}
	}

	if identity.UserID == "" && identity.UserEmail == "" && identity.TeamID == "" && identity.OrgID == "" {
		return nil, &domain.GatewayError{
			StatusCode: http.StatusUnauthorized,
			Type:       domain.ErrorTypeAuthentication,
			Code:       "missing_proxy_identity",
			Message:    "No allowlisted identity headers present in trusted proxy request",
		}
	}

	return identity, nil
}

// ExtractProxyIdentity validates cfg and authenticates r in a single call.
func ExtractProxyIdentity(r *http.Request, cfg ProxyAuthConfig) (*ProxyIdentity, error) {
	pa, err := NewProxyAuthenticator(cfg)
	if err != nil {
		return nil, &domain.GatewayError{
			StatusCode: http.StatusInternalServerError,
			Type:       domain.ErrorTypeServer,
			Code:       "invalid_proxy_auth_config",
			Message:    err.Error(),
		}
	}
	return pa.Authenticate(r)
}

func (p *ProxyAuthenticator) isIPInTrustedNets(ip net.IP) bool {
	if ip == nil {
		return false
	}
	for _, cidr := range p.trustedNets {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

func extractRawSocketIP(remoteAddr string) net.IP {
	raw := strings.TrimSpace(remoteAddr)
	if raw == "" {
		return nil
	}
	host := raw
	if h, _, err := net.SplitHostPort(raw); err == nil {
		host = h
	} else if strings.HasPrefix(raw, "[") && strings.HasSuffix(raw, "]") {
		host = strings.TrimSuffix(strings.TrimPrefix(raw, "["), "]")
	}
	ip := net.ParseIP(strings.TrimSpace(host))
	if ip == nil {
		return nil
	}
	if v4 := ip.To4(); v4 != nil {
		return v4
	}
	return ip
}

func readSingleProxyHeader(headers http.Header, headerName string) (string, error) {
	if headers == nil {
		return "", nil
	}
	values := headers.Values(headerName)
	if len(values) == 0 {
		return "", nil
	}

	var resolved string
	for _, raw := range values {
		if strings.ContainsAny(raw, "\r\n\x00") {
			return "", &domain.GatewayError{
				StatusCode: http.StatusBadRequest,
				Type:       domain.ErrorTypeInvalidRequest,
				Code:       "invalid_proxy_header",
				Message:    fmt.Sprintf("Proxy header %s contains invalid control characters", headerName),
			}
		}
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" {
			continue
		}
		if resolved == "" {
			resolved = trimmed
			continue
		}
		if resolved != trimmed {
			return "", &domain.GatewayError{
				StatusCode: http.StatusBadRequest,
				Type:       domain.ErrorTypeInvalidRequest,
				Code:       "ambiguous_proxy_headers",
				Message:    fmt.Sprintf("Conflicting values provided for proxy identity header %s", headerName),
			}
		}
	}
	return resolved, nil
}
