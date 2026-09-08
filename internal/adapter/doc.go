// Package adapter defines the provider adapter boundary and shared request
// strategies used by the gateway. Provider-specific wire translation lives in
// subpackages; new outbound HTTP clients must use internal/security/network.
// Adapter contracts and focused tests are documented in docs/CODEBASE_MAP.md.
package adapter
