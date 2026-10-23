package mcp

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/goroute-ai/ai-gateway-go/internal/auth"
	"github.com/goroute-ai/ai-gateway-go/internal/auth/upstream"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/security/network"
)

// AuthResolver resolves the appropriate upstream authentication strategy for an MCP server call.
type AuthResolver struct {
	vault     *auth.Vault
	netPolicy *network.Policy
}

// NewAuthResolver constructs an AuthResolver.
func NewAuthResolver(vault *auth.Vault, netPolicy *network.Policy) *AuthResolver {
	return &AuthResolver{
		vault:     vault,
		netPolicy: netPolicy,
	}
}

// ResolveStrategy determines the upstream authentication strategy for the given server.
func (r *AuthResolver) ResolveStrategy(
	ctx context.Context,
	server *domain.MCPServer,
	userCred *domain.MCPUserCredential,
	clientHeaders http.Header,
) (upstream.Strategy, map[string]string) {
	extraHeaders := make(map[string]string)

	// 1. Process server static headers
	for k, v := range server.StaticHeaders {
		extraHeaders[k] = v
	}

	// 2. Process x-mcp-{slug}-{header} overrides from client
	slugPrefix := "x-mcp-" + strings.ToLower(server.Slug) + "-"
	for k, v := range clientHeaders {
		lower := strings.ToLower(k)
		// Mask / filter out debug headers
		if strings.HasPrefix(lower, "x-mcp-debug-") {
			continue
		}
		if strings.HasPrefix(lower, slugPrefix) && len(v) > 0 {
			targetHeader := k[len(slugPrefix):]
			extraHeaders[targetHeader] = v[0]
		}
	}

	// 3. Resolve BYOK credential if provided
	if userCred != nil && userCred.EncryptedToken != "" && r.vault != nil {
		// Decrypt user credential
		decrypted, err := r.vault.DecryptString(userCred.EncryptedToken, userCred.EncryptedDEK)
		if err == nil && decrypted != "" {
			return upstream.NewStaticStrategy("Authorization", decrypted, extraHeaders), extraHeaders
		}
	}

	// 4. Resolve server-level authentication
	var secret string
	if server.EncryptedAuthSecret != "" && r.vault != nil {
		decrypted, err := r.vault.DecryptString(server.EncryptedAuthSecret, server.EncryptedAuthDEK)
		if err == nil {
			secret = decrypted
		}
	}

	switch server.AuthType {
	case "static":
		return upstream.NewStaticStrategy("Authorization", secret, extraHeaders), extraHeaders
	case "oauth2":
		return upstream.NewOAuth2Strategy(server.OAuth2Endpoint, server.OAuth2ClientID, secret, server.OAuth2Scopes, r.netPolicy), extraHeaders
	case "delegation":
		return upstream.NewDelegationStrategy("Authorization", true), extraHeaders
	case "vault_jwt":
		jwtStrat, err := upstream.NewJWTStrategy("gw-mcp-key", secret, "goroute-ai-gateway", []string{server.EndpointURL}, 0)
		if err == nil {
			return jwtStrat, extraHeaders
		}
	case "aws_sigv4":
		var sigCfg upstream.SigV4Config
		if err := json.Unmarshal([]byte(secret), &sigCfg); err != nil {
			parts := strings.Split(secret, ":")
			if len(parts) >= 2 {
				sigCfg.AccessKeyID = parts[0]
				sigCfg.SecretAccessKey = parts[1]
			}
		}
		if sigCfg.Region == "" {
			sigCfg.Region = server.StaticHeaders["x-amz-region"]
			if sigCfg.Region == "" {
				sigCfg.Region = "us-east-1"
			}
		}
		if sigCfg.Service == "" {
			sigCfg.Service = server.StaticHeaders["x-amz-service"]
			if sigCfg.Service == "" {
				sigCfg.Service = "bedrock"
			}
		}
		if s, err := upstream.NewSigV4Strategy(sigCfg); err == nil {
			return s, extraHeaders
		}
	case "token_exchange", "rfc8693":
		if s, err := upstream.NewTokenExchangeStrategy(upstream.TokenExchangeConfig{
			TokenEndpoint: server.OAuth2Endpoint,
			ClientID:      server.OAuth2ClientID,
			ClientSecret:  secret,
			Resource:      server.EndpointURL,
			Scope:         strings.Join(server.OAuth2Scopes, " "),
			NetPolicy:     r.netPolicy,
		}); err == nil {
			return s, extraHeaders
		}
	case "okta_id_jag":
		if s, err := upstream.NewOktaIDJAGStrategy(upstream.OktaIDJAGConfig{
			TokenEndpoint: server.OAuth2Endpoint,
			ClientID:      server.OAuth2ClientID,
			Audience:      server.OAuth2Endpoint,
			SigningKey:    secret,
			Scopes:        server.OAuth2Scopes,
			NetPolicy:     r.netPolicy,
		}); err == nil {
			return s, extraHeaders
		}
	}

	// Default: static strategy with whatever extra headers exist
	return upstream.NewStaticStrategy("Authorization", secret, extraHeaders), extraHeaders
}
