package auth

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/security/network"
)

// AuthzAction identifies the logical authorization operation evaluated by a post-auth Authorizer.
type AuthzAction string

// Supported post-authentication authorization actions evaluated by an Authorizer.
const (
	AuthzActionInference   AuthzAction = "inference:invoke"
	AuthzActionMCPToolCall AuthzAction = "mcp:tool:call"
	AuthzActionA2AInvoke   AuthzAction = "a2a:agent:invoke"
	AuthzActionAdminRead   AuthzAction = "admin:read"
	AuthzActionAdminWrite  AuthzAction = "admin:write"
)

// AuthzRequest carries the authenticated identity and target resource evaluated by a post-auth Authorizer.
type AuthzRequest struct {
	Identity     *domain.IdentityContext `json:"identity,omitempty"`
	Operator     *domain.OperatorContext `json:"operator,omitempty"`
	Action       AuthzAction             `json:"action"`
	ResourceType string                  `json:"resource_type"`
	ResourceID   string                  `json:"resource_id,omitempty"`
	Model        string                  `json:"model,omitempty"`
	MCPServer    string                  `json:"mcp_server,omitempty"`
	MCPTool      string                  `json:"mcp_tool,omitempty"`
	A2AAgent     string                  `json:"a2a_agent,omitempty"`
	HTTPMethod   string                  `json:"http_method,omitempty"`
	HTTPPath     string                  `json:"http_path,omitempty"`
	Metadata     map[string]string       `json:"metadata,omitempty"`
}

// AuthzDecision is the outcome returned by a post-auth Authorizer.
type AuthzDecision struct {
	Allow     bool   `json:"allow"`
	Reason    string `json:"reason,omitempty"`
	ErrorCode string `json:"error_code,omitempty"`
}

// Authorizer evaluates fine-grained custom or external policy decisions after authentication.
type Authorizer interface {
	Authorize(ctx context.Context, req *AuthzRequest) (*AuthzDecision, error)
}

// AuthorizerFunc adapts a plain function into an Authorizer.
type AuthorizerFunc func(ctx context.Context, req *AuthzRequest) (*AuthzDecision, error)

// Authorize invokes f(ctx, req).
func (f AuthorizerFunc) Authorize(ctx context.Context, req *AuthzRequest) (*AuthzDecision, error) {
	return f(ctx, req)
}

// EvaluateAuthorizer executes authz against req and converts denials or errors into a *domain.GatewayError.
func EvaluateAuthorizer(ctx context.Context, authz Authorizer, req *AuthzRequest) error {
	if authz == nil || req == nil {
		return nil
	}
	dec, err := authz.Authorize(ctx, req)
	if err != nil {
		var gwErr *domain.GatewayError
		if errors.As(err, &gwErr) && gwErr != nil {
			return gwErr
		}
		return &domain.GatewayError{
			StatusCode: http.StatusServiceUnavailable,
			Type:       domain.ErrorTypeServer,
			Code:       "authorizer_unavailable",
			Message:    "Custom authorization policy check failed: " + err.Error(),
			Retryable:  true,
		}
	}
	if dec == nil || !dec.Allow {
		code := "custom_authorization_denied"
		msg := "Request denied by custom authorization policy"
		if dec != nil {
			if strings.TrimSpace(dec.ErrorCode) != "" {
				code = strings.TrimSpace(dec.ErrorCode)
			}
			if strings.TrimSpace(dec.Reason) != "" {
				msg = strings.TrimSpace(dec.Reason)
			}
		}
		return &domain.GatewayError{
			StatusCode: http.StatusForbidden,
			Type:       domain.ErrorTypePermission,
			Code:       code,
			Message:    msg,
		}
	}
	return nil
}

// ChainAuthorizer runs multiple Authorizers sequentially and fails closed on the first denial or error.
type ChainAuthorizer struct {
	authorizers []Authorizer
}

// NewChainAuthorizer combines non-nil authorizers into a sequential chain.
func NewChainAuthorizer(authorizers ...Authorizer) Authorizer {
	var list []Authorizer
	for _, a := range authorizers {
		if a != nil {
			list = append(list, a)
		}
	}
	if len(list) == 0 {
		return nil
	}
	if len(list) == 1 {
		return list[0]
	}
	return &ChainAuthorizer{authorizers: list}
}

// Authorize evaluates each authorizer in order.
func (c *ChainAuthorizer) Authorize(ctx context.Context, req *AuthzRequest) (*AuthzDecision, error) {
	for _, a := range c.authorizers {
		dec, err := a.Authorize(ctx, req)
		if err != nil {
			return nil, err
		}
		if dec == nil || !dec.Allow {
			return dec, nil
		}
	}
	return &AuthzDecision{Allow: true}, nil
}

// ExternalAuthorizerConfig configures a standalone HTTP Webhook or OPA REST API policy authorizer.
type ExternalAuthorizerConfig struct {
	Mode       string // "webhook" or "opa"
	URL        string
	Timeout    time.Duration
	FailMode   string // "closed" (default) or "open"
	CacheTTL   time.Duration
	AuthHeader string // Optional Authorization header value (e.g. "Bearer ...")
	HMACSecret string // Optional secret for X-GoRoute-Signature-256
}

type cachedAuthzDecision struct {
	decision  AuthzDecision
	expiresAt time.Time
}

// ExternalAuthorizer delegates post-auth policy checks to an external Webhook or OPA Data API
// strictly over GoRoute's SSRF-protected outbound network.Policy.
type ExternalAuthorizer struct {
	mode       string
	url        string
	timeout    time.Duration
	failOpen   bool
	cacheTTL   time.Duration
	authHeader string
	hmacSecret string
	httpClient *http.Client
	now        func() time.Time

	cacheMu sync.RWMutex
	cache   map[string]cachedAuthzDecision
}

const maxExternalAuthorizerBodyBytes = 64 << 10 // 64 KiB

// NewExternalAuthorizer builds an SSRF-safe external Webhook or OPA authorizer.
func NewExternalAuthorizer(cfg ExternalAuthorizerConfig, netPolicy *network.Policy) (*ExternalAuthorizer, error) {
	mode := strings.ToLower(strings.TrimSpace(cfg.Mode))
	if mode == "" {
		mode = "webhook"
	}
	if mode != "webhook" && mode != "opa" {
		return nil, fmt.Errorf("external authorizer mode must be \"webhook\" or \"opa\", got %q", cfg.Mode)
	}
	endpoint := strings.TrimSpace(cfg.URL)
	if endpoint == "" {
		return nil, fmt.Errorf("external authorizer url is required")
	}
	failMode := strings.ToLower(strings.TrimSpace(cfg.FailMode))
	if failMode == "" {
		failMode = "closed"
	}
	if failMode != "closed" && failMode != "open" {
		return nil, fmt.Errorf("external authorizer fail_mode must be \"closed\" or \"open\", got %q", cfg.FailMode)
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 500 * time.Millisecond
	}
	if timeout > 5*time.Second {
		timeout = 5 * time.Second
	}

	client := network.NewHTTPClient(netPolicy)
	client.Timeout = timeout

	if failMode == "open" {
		slog.Warn("security: external_authorizer configured with fail_mode=open; policy outages will allow requests",
			"mode", mode, "url", endpoint)
	}

	return &ExternalAuthorizer{
		mode:       mode,
		url:        endpoint,
		timeout:    timeout,
		failOpen:   failMode == "open",
		cacheTTL:   cfg.CacheTTL,
		authHeader: strings.TrimSpace(cfg.AuthHeader),
		hmacSecret: strings.TrimSpace(cfg.HMACSecret),
		httpClient: client,
		now:        time.Now,
		cache:      make(map[string]cachedAuthzDecision),
	}, nil
}

// Authorize posts req to the configured Webhook or OPA endpoint and parses the decision.
func (e *ExternalAuthorizer) Authorize(ctx context.Context, req *AuthzRequest) (*AuthzDecision, error) {
	if e == nil || req == nil {
		return &AuthzDecision{Allow: true}, nil
	}
	cacheKey := ""
	if e.cacheTTL > 0 {
		cacheKey = externalAuthzCacheKey(req)
		if dec, hit := e.getCached(cacheKey); hit {
			return &dec, nil
		}
	}

	var payload any = req
	if e.mode == "opa" {
		payload = map[string]any{"input": req}
	}
	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return e.handleFailure(ctx, fmt.Errorf("marshal external authorizer payload: %w", err))
	}

	reqCtx, cancel := context.WithTimeout(ctx, e.timeout)
	defer cancel()

	httpReq, err := http.NewRequestWithContext(reqCtx, http.MethodPost, e.url, bytes.NewReader(bodyBytes))
	if err != nil {
		return e.handleFailure(ctx, err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")
	if e.authHeader != "" {
		httpReq.Header.Set("Authorization", e.authHeader)
	}
	if e.hmacSecret != "" {
		mac := hmac.New(sha256.New, []byte(e.hmacSecret))
		_, _ = mac.Write(bodyBytes)
		httpReq.Header.Set("X-GoRoute-Signature-256", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	}

	resp, err := e.httpClient.Do(httpReq)
	if err != nil {
		return e.handleFailure(ctx, err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, readErr := io.ReadAll(io.LimitReader(resp.Body, maxExternalAuthorizerBodyBytes))
	if readErr != nil {
		return e.handleFailure(ctx, readErr)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return e.handleFailure(ctx, fmt.Errorf("external authorizer returned HTTP %d", resp.StatusCode))
	}

	dec, parseErr := parseExternalAuthzResponse(e.mode, respBody)
	if parseErr != nil {
		return e.handleFailure(ctx, parseErr)
	}
	if cacheKey != "" {
		e.putCached(cacheKey, *dec)
	}
	return dec, nil
}

func (e *ExternalAuthorizer) handleFailure(ctx context.Context, err error) (*AuthzDecision, error) {
	if e.failOpen {
		slog.WarnContext(ctx, "external authorizer error ignored due to fail_mode=open", "error", err)
		return &AuthzDecision{Allow: true}, nil
	}
	return nil, &domain.GatewayError{
		StatusCode: http.StatusServiceUnavailable,
		Type:       domain.ErrorTypeServer,
		Code:       "external_authorizer_unavailable",
		Message:    "External authorization service unavailable",
		Retryable:  true,
	}
}

func parseExternalAuthzResponse(mode string, body []byte) (*AuthzDecision, error) {
	if mode == "opa" {
		var envelope struct {
			Result json.RawMessage `json:"result"`
		}
		if err := json.Unmarshal(body, &envelope); err != nil {
			return nil, fmt.Errorf("decode opa response: %w", err)
		}
		if len(envelope.Result) == 0 || string(envelope.Result) == "null" {
			return &AuthzDecision{Allow: false, Reason: "OPA policy returned empty result"}, nil
		}
		var allowBool bool
		if err := json.Unmarshal(envelope.Result, &allowBool); err == nil {
			return &AuthzDecision{Allow: allowBool}, nil
		}
		var dec AuthzDecision
		if err := json.Unmarshal(envelope.Result, &dec); err != nil {
			return nil, fmt.Errorf("decode opa result object: %w", err)
		}
		return &dec, nil
	}

	var dec AuthzDecision
	if err := json.Unmarshal(body, &dec); err != nil {
		return nil, fmt.Errorf("decode webhook authorizer response: %w", err)
	}
	return &dec, nil
}

func (e *ExternalAuthorizer) getCached(key string) (AuthzDecision, bool) {
	e.cacheMu.RLock()
	entry, ok := e.cache[key]
	e.cacheMu.RUnlock()
	if !ok {
		return AuthzDecision{}, false
	}
	if e.now().After(entry.expiresAt) {
		e.cacheMu.Lock()
		delete(e.cache, key)
		e.cacheMu.Unlock()
		return AuthzDecision{}, false
	}
	return entry.decision, true
}

func (e *ExternalAuthorizer) putCached(key string, dec AuthzDecision) {
	e.cacheMu.Lock()
	defer e.cacheMu.Unlock()
	if len(e.cache) >= 4096 {
		now := e.now()
		for k, v := range e.cache {
			if now.After(v.expiresAt) {
				delete(e.cache, k)
			}
		}
		if len(e.cache) >= 4096 {
			clear(e.cache)
		}
	}
	e.cache[key] = cachedAuthzDecision{
		decision:  dec,
		expiresAt: e.now().Add(e.cacheTTL),
	}
}

func externalAuthzCacheKey(req *AuthzRequest) string {
	h := sha256.New()
	write := func(s string) {
		_, _ = h.Write([]byte(s))
		_, _ = h.Write([]byte{0})
	}
	if req.Identity != nil {
		write(req.Identity.OrgID)
		write(req.Identity.VirtualKeyID)
		write(req.Identity.UserID)
		write(req.Identity.TeamID)
		write(req.Identity.ProjectID)
		write(string(req.Identity.Role))
	}
	if req.Operator != nil {
		write(req.Operator.OrgID)
		write(req.Operator.ActorID)
		write(string(req.Operator.Role))
	}
	write(string(req.Action))
	write(req.ResourceType)
	write(req.ResourceID)
	write(req.Model)
	write(req.MCPServer)
	write(req.MCPTool)
	write(req.A2AAgent)
	return hex.EncodeToString(h.Sum(nil))
}
