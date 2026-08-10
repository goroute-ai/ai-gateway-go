// Package network implements centralized outbound SSRF (Server-Side Request Forgery)
// protection, DNS resolution pinning, and hardened HTTP transport policies for all gateway egress.
//
// All outbound network traffic initiated by the gateway—including upstream LLM provider calls,
// MCP server connections, and A2A agent delegations—must pass through this package's custom
// http.Transport to guarantee strict network boundary isolation.
//
// Security Controls:
//   - Zero Ambient Proxy: Disables environment-inherited HTTP_PROXY / HTTPS_PROXY settings (Proxy: nil).
//   - Connect-Time IP Pinning: Resolves DNS at dial time, checks IP addresses against private network
//     rules (RFC 1918, RFC 4193, loopback, link-local, cloud metadata 169.254.169.254), and binds
//     the TCP connection directly to the validated IP.
//   - Decoupled Security Policies: Explicitly decouples AllowPrivateNetworks (e.g. AllowedPrivateCIDRs)
//     from AllowInsecureHTTP (plain HTTP scheme).
//   - Redirect Re-Validation: Intercepts all HTTP redirects via CheckRedirect to re-verify target URLs
//     against SSRF policies, preventing redirect-based perimeter escape.
//   - IPv6 Canonicalization: Normalizes IPv4-mapped IPv6 addresses (netip.Addr.Unmap) and enforces
//     dual-stack validation.
package network
