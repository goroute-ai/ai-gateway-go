// Package upstream provides decoupled authentication strategies for outbound upstream
// provider, MCP server, and A2A agent connections.
//
// In GoRoute AI Gateway, caller identity (Virtual API Keys presented by the client) and
// upstream credentials (secrets used by the gateway to authenticate to external providers)
// are strictly separated. This package encapsulates the upstream authentication lifecycle.
//
// Supported Strategies:
//   - Static Headers: Attaches static API keys or bearer tokens (e.g. Gemini, OpenAI, Claude).
//   - M2M OAuth2 Client Credentials: Automatically fetches, caches, and refreshes OAuth2 bearer
//     tokens with proactive renewal before expiration.
//   - KMS/Vault Signed JWT: Dynamically signs JSON Web Tokens using asymmetric keys (RS256/ES256)
//     stored in HashiCorp Vault or Cloud KMS with mandatory audience binding.
//   - Explicit Identity Delegation: Safely propagates caller identity metadata via X-Gateway-*
//     headers while stripping ambient or sensitive authorization headers.
//   - AWS SigV4 Signer: Signs outbound HTTP requests to AWS Bedrock, SageMaker, or API Gateway endpoints
//     using AWS Signature Version 4 with canonical request hashing and timestamped headers.
//   - Client Identifier Metadata Document (CIMD & S256 PKCE): Implements RFC 7591 and MCP 2026-07-28
//     client identity metadata verification with SHA-256 Proof Key for Code Exchange (PKCE).
//   - RFC 9207 & RFC 8707 Protection: Validates authorization response issuer parameters and resource
//     indicators against strict upstream tenant origins, mitigating authorization code mix-up attacks.
//   - RFC 8693 OAuth 2.0 Token Exchange: Exchanges caller or service tokens for scoped upstream tokens
//     (e.g., On-Behalf-Of flows) with TTL-aware in-memory caching and proactive cache eviction.
//   - Okta Identity Assertion Grant (JAG): Provides cross-boundary identity assertions for enterprise Okta
//     federation topologies.
package upstream
