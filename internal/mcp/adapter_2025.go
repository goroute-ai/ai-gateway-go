package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/goroute-ai/ai-gateway-go/internal/auth/upstream"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/security/network"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
	"github.com/redis/go-redis/v9"
)

// MCP2025Session holds the state mapped to a 2025-11-25 session.
type MCP2025Session struct {
	GatewaySessionID     string    `json:"gw_session_id"`
	ServerID             string    `json:"server_id"`
	UpstreamSessionID    string    `json:"upstream_session_id"`
	UpstreamAffinityHint string    `json:"upstream_affinity_hint,omitempty"`
	AuthPrincipalDigest  string    `json:"auth_principal_digest"`
	ExpiresAt            time.Time `json:"expires_at"`
}

// StreamableHTTP2025Adapter provides stateful compatibility for MCP 2025-11-25 servers.
type StreamableHTTP2025Adapter struct {
	httpClient *http.Client
	redis      *storage.RedisFabric
	memMu      sync.RWMutex
	memStore   map[string]*MCP2025Session // In-memory fallback if Redis is nil
	sessionTTL time.Duration
}

// NewStreamableHTTP2025Adapter creates a new 2025 compatibility adapter.
func NewStreamableHTTP2025Adapter(netPolicy *network.Policy, redisFabric *storage.RedisFabric) *StreamableHTTP2025Adapter {
	return &StreamableHTTP2025Adapter{
		httpClient: network.NewHTTPClient(netPolicy),
		redis:      redisFabric,
		memStore:   make(map[string]*MCP2025Session),
		sessionTTL: 15 * time.Minute,
	}
}

func (a *StreamableHTTP2025Adapter) RoundTrip(
	ctx context.Context,
	server *domain.MCPServer,
	authStrategy upstream.Strategy,
	authCtx *upstream.UpstreamAuthContext,
	reqBytes []byte,
	clientHeaders http.Header,
) (*JSONRPCResponse, http.Header, error) {
	if server == nil {
		return nil, nil, errors.New("mcp: nil server")
	}

	gwSessionID := strings.TrimSpace(clientHeaders.Get("Mcp-Session-Id"))
	var session *MCP2025Session
	var err error

	// If client provided a session ID, validate and resolve session state
	if gwSessionID != "" {
		session, err = a.getSession(ctx, gwSessionID)
		if err != nil || session == nil {
			return nil, nil, &JSONRPCError{
				Code:    CodeSessionExpired,
				Message: "session_expired: MCP 2025 session has expired or is invalid. Please re-initialize.",
			}
		}

		// Security: Validate principal digest to prevent session hijacking
		if authCtx != nil {
			currentDigest := authCtx.PrincipalDigest()
			if session.AuthPrincipalDigest != "" && session.AuthPrincipalDigest != currentDigest {
				return nil, nil, &JSONRPCError{
					Code:    CodeInvalidRequest,
					Message: "Forbidden: session belongs to a different caller principal",
				}
			}
		}
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, server.EndpointURL, bytes.NewReader(reqBytes))
	if err != nil {
		return nil, nil, fmt.Errorf("create 2025 mcp request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json, text/event-stream")

	// Forward Mcp-* headers, mapping to upstream session ID if resolved
	for k, v := range clientHeaders {
		if strings.HasPrefix(strings.ToLower(k), "mcp-") {
			httpReq.Header[k] = v
		}
	}
	if session != nil && session.UpstreamSessionID != "" {
		httpReq.Header.Set("Mcp-Session-Id", session.UpstreamSessionID)
	}

	// Apply upstream authentication strategy
	if authStrategy != nil {
		if err := authStrategy.Apply(ctx, httpReq, authCtx); err != nil {
			return nil, nil, fmt.Errorf("apply upstream auth: %w", err)
		}
	}

	resp, err := a.httpClient.Do(httpReq)
	if err != nil {
		return nil, nil, fmt.Errorf("upstream 2025 request failed: %w", err)
	}
	defer resp.Body.Close()

	// If upstream returned 404 or 410, session has expired on upstream pod
	if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusGone {
		if gwSessionID != "" {
			_ = a.deleteSession(ctx, gwSessionID)
		}
		return nil, resp.Header, &JSONRPCError{
			Code:    CodeSessionExpired,
			Message: "session_expired: upstream MCP server reported session expired (404/410). Please re-initialize.",
		}
	}

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
	if err != nil {
		return nil, nil, fmt.Errorf("read 2025 mcp response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, resp.Header, &JSONRPCError{
			Code:    CodeInternalError,
			Message: fmt.Sprintf("upstream returned HTTP status %d: %s", resp.StatusCode, string(respBody)),
		}
	}

	var jsonResp JSONRPCResponse
	if err := json.Unmarshal(respBody, &jsonResp); err != nil {
		return nil, resp.Header, &JSONRPCError{
			Code:    CodeParseError,
			Message: fmt.Sprintf("invalid json-rpc response from upstream: %v", err),
		}
	}

	// Check if upstream returned a new Mcp-Session-Id (e.g. from initialize handshake)
	upstreamSessID := resp.Header.Get("Mcp-Session-Id")
	if upstreamSessID != "" {
		newGWSessID := "mcp25_sess_" + uuid.NewString()
		principalDigest := ""
		if authCtx != nil {
			principalDigest = authCtx.PrincipalDigest()
		}
		newSession := &MCP2025Session{
			GatewaySessionID:    newGWSessID,
			ServerID:            server.ID,
			UpstreamSessionID:   upstreamSessID,
			AuthPrincipalDigest: principalDigest,
			ExpiresAt:           time.Now().UTC().Add(a.sessionTTL),
		}
		_ = a.saveSession(ctx, newSession)

		// Expose the gateway-managed session ID to client
		resp.Header.Set("Mcp-Session-Id", newGWSessID)
	}

	return &jsonResp, resp.Header, nil
}

func (a *StreamableHTTP2025Adapter) getSession(ctx context.Context, gwSessionID string) (*MCP2025Session, error) {
	if a.redis != nil {
		res, err := a.redis.Execute(func(rdb redis.UniversalClient) (any, error) {
			return rdb.Get(ctx, "gw:mcp25:sess:"+gwSessionID).Result()
		})
		if err == nil {
			if jsonStr, ok := res.(string); ok && jsonStr != "" {
				var sess MCP2025Session
				if err := json.Unmarshal([]byte(jsonStr), &sess); err == nil {
					return &sess, nil
				}
			}
		}
	}

	a.memMu.RLock()
	defer a.memMu.RUnlock()
	sess, ok := a.memStore[gwSessionID]
	if !ok || time.Now().UTC().After(sess.ExpiresAt) {
		return nil, errors.New("session not found")
	}
	return sess, nil
}

func (a *StreamableHTTP2025Adapter) saveSession(ctx context.Context, sess *MCP2025Session) error {
	data, _ := json.Marshal(sess)
	if a.redis != nil {
		_, _ = a.redis.Execute(func(rdb redis.UniversalClient) (any, error) {
			return rdb.Set(ctx, "gw:mcp25:sess:"+sess.GatewaySessionID, data, a.sessionTTL).Result()
		})
	}

	a.memMu.Lock()
	defer a.memMu.Unlock()
	a.memStore[sess.GatewaySessionID] = sess
	return nil
}

func (a *StreamableHTTP2025Adapter) deleteSession(ctx context.Context, gwSessionID string) error {
	if a.redis != nil {
		_, _ = a.redis.Execute(func(rdb redis.UniversalClient) (any, error) {
			return rdb.Del(ctx, "gw:mcp25:sess:"+gwSessionID).Result()
		})
	}

	a.memMu.Lock()
	defer a.memMu.Unlock()
	delete(a.memStore, gwSessionID)
	return nil
}
