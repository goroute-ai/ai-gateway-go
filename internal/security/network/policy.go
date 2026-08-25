package network

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/config"
)

var (
	ErrBlockedScheme         = errors.New("network: scheme is forbidden by outbound policy")
	ErrInsecureHTTPBlocked   = errors.New("network: insecure HTTP scheme is forbidden (allow_insecure_http is false)")
	ErrPrivateNetworkBlocked = errors.New("network: private/local network address is forbidden by SSRF policy")
	ErrCloudMetadataBlocked  = errors.New("network: cloud metadata service address is strictly forbidden")
	ErrBlockedIP             = errors.New("network: destination IP is in the forbidden list")
	ErrTooManyRedirects      = errors.New("network: maximum allowed redirect limit exceeded")
)

var (
	// Default blocked cloud metadata IPs
	metadataIPv4 = net.ParseIP("169.254.169.254")
	metadataIPv6 = net.ParseIP("fd00:ec2::254")

	// Standard private/local IP CIDR ranges
	privateCIDRs []*net.IPNet
)

func init() {
	ranges := []string{
		"127.0.0.0/8",    // Loopback IPv4
		"::1/128",        // Loopback IPv6
		"10.0.0.0/8",     // RFC 1918
		"172.16.0.0/12",  // RFC 1918
		"192.168.0.0/16", // RFC 1918
		"169.254.0.0/16", // Link-local IPv4
		"fe80::/10",      // Link-local IPv6
		"fc00::/7",       // Unique local IPv6 (ULA)
		"100.64.0.0/10",  // Carrier-grade NAT
		"0.0.0.0/8",      // Current network
	}
	for _, r := range ranges {
		_, ipNet, err := net.ParseCIDR(r)
		if err == nil {
			privateCIDRs = append(privateCIDRs, ipNet)
		}
	}
}

// Policy specifies rules for outbound HTTP network requests to prevent SSRF and protocol smuggling.
type Policy struct {
	AllowPrivateNetworks bool
	AllowedPrivateCIDRs  []*net.IPNet
	AllowInsecureHTTP    bool
	AllowedSchemes       map[string]bool
	BlockedIPs           []net.IP
	DialTimeout          time.Duration
	MaxRedirects         int
	EgressProxyURL       string
}

// NewPolicy constructs an active network security policy from configuration.
func NewPolicy(cfg config.OutboundSSRFConfig) (*Policy, error) {
	p := &Policy{
		AllowPrivateNetworks: cfg.AllowPrivateNetworks,
		AllowInsecureHTTP:    cfg.AllowInsecureHTTP,
		AllowedSchemes:       make(map[string]bool),
		DialTimeout:          cfg.DialTimeout,
		MaxRedirects:         cfg.MaxRedirects,
		EgressProxyURL:       strings.TrimSpace(cfg.EgressProxyURL),
	}

	if p.DialTimeout <= 0 {
		p.DialTimeout = 10 * time.Second
	}
	if p.MaxRedirects <= 0 {
		p.MaxRedirects = 3
	}

	schemes := cfg.AllowedSchemes
	if len(schemes) == 0 {
		schemes = []string{"https", "http"}
	}
	for _, s := range schemes {
		p.AllowedSchemes[strings.ToLower(strings.TrimSpace(s))] = true
	}

	for _, cidr := range cfg.AllowedPrivateCIDRs {
		_, ipNet, err := net.ParseCIDR(strings.TrimSpace(cidr))
		if err != nil {
			return nil, fmt.Errorf("parse allowed private cidr %q: %w", cidr, err)
		}
		p.AllowedPrivateCIDRs = append(p.AllowedPrivateCIDRs, ipNet)
	}

	for _, ipStr := range cfg.BlockedIPs {
		ip := net.ParseIP(strings.TrimSpace(ipStr))
		if ip != nil {
			p.BlockedIPs = append(p.BlockedIPs, ip)
		}
	}

	return p, nil
}

// ValidateURL checks URL scheme, host, and port invariants.
func (p *Policy) ValidateURL(u *url.URL) error {
	if u == nil {
		return errors.New("network: nil URL")
	}
	scheme := strings.ToLower(u.Scheme)
	if !p.AllowedSchemes[scheme] {
		return fmt.Errorf("%w: scheme %q not allowed", ErrBlockedScheme, scheme)
	}
	if scheme == "http" && !p.AllowInsecureHTTP {
		return ErrInsecureHTTPBlocked
	}

	hostname := strings.ToLower(u.Hostname())
	if hostname == "" {
		return errors.New("network: missing hostname in URL")
	}

	// Strictly block known cloud metadata hostnames
	if hostname == "metadata.google.internal" || hostname == "metadata" || hostname == "instance-data" {
		return ErrCloudMetadataBlocked
	}

	// If hostname is an IP literal, validate immediately
	if ip := net.ParseIP(hostname); ip != nil {
		return p.ValidateIP(ip)
	}

	return nil
}

// ValidateIP tests whether an IP address is permitted under the policy.
func (p *Policy) ValidateIP(ip net.IP) error {
	if ip == nil {
		return errors.New("network: nil IP")
	}

	// Normalize IPv4-mapped IPv6 addresses (e.g. ::ffff:127.0.0.1 -> 127.0.0.1)
	cleanIP := ip
	if unmapped := ip.To4(); unmapped != nil {
		cleanIP = unmapped
	}

	// Cloud metadata check is absolute and non-bypassable
	if cleanIP.Equal(metadataIPv4) || cleanIP.Equal(metadataIPv6) {
		return ErrCloudMetadataBlocked
	}

	// Blocked IPs check
	for _, blocked := range p.BlockedIPs {
		target := blocked
		if unmapped := blocked.To4(); unmapped != nil {
			target = unmapped
		}
		if cleanIP.Equal(target) {
			return ErrBlockedIP
		}
	}

	// Check if IP falls into any standard private CIDR range
	isPrivate := false
	for _, ipNet := range privateCIDRs {
		if ipNet.Contains(cleanIP) {
			isPrivate = true
			break
		}
	}

	if isPrivate {
		// If private networks are globally disallowed, check if explicitly allowlisted in AllowedPrivateCIDRs
		if !p.AllowPrivateNetworks {
			allowed := false
			for _, allowedCIDR := range p.AllowedPrivateCIDRs {
				if allowedCIDR.Contains(cleanIP) {
					allowed = true
					break
				}
			}
			if !allowed {
				return fmt.Errorf("%w: %s is in private IP space", ErrPrivateNetworkBlocked, cleanIP.String())
			}
		}
	}

	return nil
}
