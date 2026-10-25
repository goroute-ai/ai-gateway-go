package mcp

import (
	"bytes"
	"container/list"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"encoding/json"
	"github.com/google/uuid"
	"github.com/goroute-ai/ai-gateway-go/internal/auth/upstream"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/security/network"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
	"github.com/redis/go-redis/v9"
)

// StatefulMCPSession holds gateway-scoped session affinity mapped to a stateful Streamable HTTP release
// (2025-03-26, 2025-06-18, or 2025-11-25).
type StatefulMCPSession struct {
	GatewaySessionID     string    `json:"gw_session_id"`
	ServerID             string    `json:"server_id"`
	ProtocolVersion      string    `json:"protocol_version"`
	UpstreamSessionID    string    `json:"upstream_session_id"`
	UpstreamAffinityHint string    `json:"upstream_affinity_hint,omitempty"`
	AuthPrincipalDigest  string    `json:"auth_principal_digest"`
	ExpiresAt            time.Time `json:"expires_at"`
}

// MCP2025Session aliases StatefulMCPSession for existing package consumers.
type MCP2025Session = StatefulMCPSession

const maxStatefulMCPSessions = 4096

// StatefulStreamableTransport implements stateful Streamable HTTP transport for MCP releases
// 2025-03-26, 2025-06-18, and 2025-11-25 with Redis/LRU session mapping and principal digest isolation.
type StatefulStreamableTransport struct {
	httpClient *http.Client
	redis      *storage.RedisFabric
	memMu      sync.Mutex
	memStore   map[string]*list.Element
	memLRU     *list.List
	maxMem     int
	sessionTTL time.Duration
}

// StreamableHTTP2025Adapter aliases StatefulStreamableTransport for backwards test compatibility.
type StreamableHTTP2025Adapter = StatefulStreamableTransport

type statefulSessionLRUEntry struct {
	key  string
	sess *StatefulMCPSession
}

// NewStatefulStreamableTransport creates a new stateful Streamable HTTP transport adapter.
func NewStatefulStreamableTransport(netPolicy *network.Policy, redisFabric *storage.RedisFabric) *StatefulStreamableTransport {
	return &StatefulStreamableTransport{
		httpClient: network.NewHTTPClient(netPolicy),
		redis:      redisFabric,
		memStore:   make(map[string]*list.Element),
		memLRU:     list.New(),
		maxMem:     maxStatefulMCPSessions,
		sessionTTL: 15 * time.Minute,
	}
}

// NewStreamableHTTP2025Adapter constructs a StatefulStreamableTransport.
func NewStreamableHTTP2025Adapter(netPolicy *network.Policy, redisFabric *storage.RedisFabric) *StreamableHTTP2025Adapter {
	return NewStatefulStreamableTransport(netPolicy, redisFabric)
}

func (a *StatefulStreamableTransport) RoundTrip(
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
	var session *StatefulMCPSession
	if gwSessionID != "" {
		resolved, err := a.getSession(ctx, server.ID, gwSessionID)
		if err != nil || resolved == nil {
			return nil, nil, &JSONRPCError{
				Code:    CodeSessionExpired,
				Message: "session_expired: MCP stateful session has expired or is invalid. Please re-initialize.",
			}
		}
		if authCtx != nil {
			currentDigest := authCtx.PrincipalDigest()
			if resolved.AuthPrincipalDigest != "" && resolved.AuthPrincipalDigest != currentDigest {
				return nil, nil, &JSONRPCError{
					Code:    CodeInvalidRequest,
					Message: "Forbidden: session belongs to a different caller principal",
				}
			}
		}
		session = resolved
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, server.EndpointURL, bytes.NewReader(reqBytes))
	if err != nil {
		return nil, nil, fmt.Errorf("create stateful mcp request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json, text/event-stream")

	for k, v := range clientHeaders {
		if strings.HasPrefix(strings.ToLower(k), "mcp-") {
			httpReq.Header[k] = v
		}
	}
	targetVersion := strings.TrimSpace(server.ProtocolVersion)
	if targetVersion == domain.MCPProtocolVersion20250618 || targetVersion == domain.MCPProtocolVersion20251125 {
		httpReq.Header.Set("MCP-Protocol-Version", targetVersion)
	}
	if session != nil && session.UpstreamSessionID != "" {
		httpReq.Header.Set("Mcp-Session-Id", session.UpstreamSessionID)
	}

	if authStrategy != nil {
		if err := authStrategy.Apply(ctx, httpReq, authCtx); err != nil {
			return nil, nil, fmt.Errorf("apply upstream auth: %w", err)
		}
	}

	resp, err := a.httpClient.Do(httpReq)
	if err != nil {
		return nil, nil, fmt.Errorf("upstream stateful mcp request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusGone {
		if gwSessionID != "" {
			_ = a.deleteSession(ctx, gwSessionID)
		}
		return nil, resp.Header, &JSONRPCError{
			Code:    CodeSessionExpired,
			Message: "session_expired: upstream MCP server reported session expired (404/410). Please re-initialize.",
		}
	}

	jsonResp, rpcErr := parseMCPHTTPResponse(resp)
	if rpcErr != nil {
		return nil, resp.Header, rpcErr
	}

	upstreamSessID := resp.Header.Get("Mcp-Session-Id")
	if upstreamSessID != "" {
		newGWSessID := "mcp_sess_" + uuid.NewString()
		principalDigest := ""
		if authCtx != nil {
			principalDigest = authCtx.PrincipalDigest()
		}
		newSession := &StatefulMCPSession{
			GatewaySessionID:    newGWSessID,
			ServerID:            server.ID,
			ProtocolVersion:     targetVersion,
			UpstreamSessionID:   upstreamSessID,
			AuthPrincipalDigest: principalDigest,
			ExpiresAt:           time.Now().UTC().Add(a.sessionTTL),
		}
		_ = a.saveSession(ctx, newSession)
		resp.Header.Set("Mcp-Session-Id", newGWSessID)
	}

	return jsonResp, resp.Header, nil
}

func (a *StatefulStreamableTransport) getSession(ctx context.Context, serverID, gwSessionID string) (*StatefulMCPSession, error) {
	if a.redis != nil {
		res, err := a.redis.Execute(func(rdb redis.UniversalClient) (any, error) {
			return rdb.Get(ctx, "gw:mcp25:sess:"+gwSessionID).Result()
		})
		if err == nil {
			if jsonStr, ok := res.(string); ok && jsonStr != "" {
				var sess StatefulMCPSession
				if err := json.Unmarshal([]byte(jsonStr), &sess); err == nil {
					if sess.ServerID != serverID {
						return nil, errors.New("session does not belong to target server")
					}
					return &sess, nil
				}
			}
		}
	}

	a.memMu.Lock()
	defer a.memMu.Unlock()
	elem, ok := a.memStore[gwSessionID]
	if !ok {
		return nil, errors.New("session not found")
	}
	entry := elem.Value.(*statefulSessionLRUEntry)
	if time.Now().UTC().After(entry.sess.ExpiresAt) {
		a.memLRU.Remove(elem)
		delete(a.memStore, gwSessionID)
		return nil, errors.New("session not found")
	}
	if entry.sess.ServerID != serverID {
		return nil, errors.New("session does not belong to target server")
	}
	a.memLRU.MoveToFront(elem)
	return entry.sess, nil
}

func (a *StatefulStreamableTransport) saveSession(ctx context.Context, sess *StatefulMCPSession) error {
	data, _ := json.Marshal(sess)
	if a.redis != nil {
		_, _ = a.redis.Execute(func(rdb redis.UniversalClient) (any, error) {
			return rdb.Set(ctx, "gw:mcp25:sess:"+sess.GatewaySessionID, data, a.sessionTTL).Result()
		})
	}

	a.memMu.Lock()
	defer a.memMu.Unlock()
	now := time.Now().UTC()
	if elem, ok := a.memStore[sess.GatewaySessionID]; ok {
		elem.Value.(*statefulSessionLRUEntry).sess = sess
		a.memLRU.MoveToFront(elem)
		return nil
	}
	for a.memLRU.Len() >= a.maxMem {
		tail := a.memLRU.Back()
		if tail == nil {
			break
		}
		tailEntry := tail.Value.(*statefulSessionLRUEntry)
		a.memLRU.Remove(tail)
		delete(a.memStore, tailEntry.key)
	}
	if tail := a.memLRU.Back(); tail != nil {
		if tailEntry := tail.Value.(*statefulSessionLRUEntry); now.After(tailEntry.sess.ExpiresAt) {
			a.memLRU.Remove(tail)
			delete(a.memStore, tailEntry.key)
		}
	}
	elem := a.memLRU.PushFront(&statefulSessionLRUEntry{key: sess.GatewaySessionID, sess: sess})
	a.memStore[sess.GatewaySessionID] = elem
	return nil
}

func (a *StatefulStreamableTransport) deleteSession(ctx context.Context, gwSessionID string) error {
	if a.redis != nil {
		_, _ = a.redis.Execute(func(rdb redis.UniversalClient) (any, error) {
			return rdb.Del(ctx, "gw:mcp25:sess:"+gwSessionID).Result()
		})
	}

	a.memMu.Lock()
	defer a.memMu.Unlock()
	if elem, ok := a.memStore[gwSessionID]; ok {
		a.memLRU.Remove(elem)
		delete(a.memStore, gwSessionID)
	}
	return nil
}

// parseMCPHTTPResponse parses direct JSON, 202 Accepted (notification ack), or text/event-stream SSE MCP responses.
func parseMCPHTTPResponse(resp *http.Response) (*JSONRPCResponse, *JSONRPCError) {
	if resp.StatusCode == http.StatusAccepted || resp.StatusCode == http.StatusNoContent {
		return &JSONRPCResponse{JSONRPC: "2.0"}, nil
	}

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
	if err != nil {
		return nil, &JSONRPCError{
			Code:    CodeInternalError,
			Message: fmt.Sprintf("read mcp response: %v", err),
		}
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, &JSONRPCError{
			Code:    CodeInternalError,
			Message: fmt.Sprintf("upstream returned HTTP status %d: %s", resp.StatusCode, string(respBody)),
		}
	}

	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	if strings.Contains(ct, "text/event-stream") {
		parsed, err := extractFinalJSONRPCFromSSE(respBody)
		if err != nil {
			return nil, &JSONRPCError{
				Code:    CodeParseError,
				Message: err.Error(),
			}
		}
		return parsed, nil
	}

	if len(bytes.TrimSpace(respBody)) == 0 {
		return &JSONRPCResponse{JSONRPC: "2.0"}, nil
	}

	var jsonResp JSONRPCResponse
	if err := json.Unmarshal(respBody, &jsonResp); err != nil {
		return nil, &JSONRPCError{
			Code:    CodeParseError,
			Message: fmt.Sprintf("invalid json-rpc response from upstream: %v", err),
		}
	}
	return &jsonResp, nil
}

func extractFinalJSONRPCFromSSE(raw []byte) (*JSONRPCResponse, error) {
	lines := strings.Split(string(raw), "\n")
	var dataBuf strings.Builder
	var lastResp *JSONRPCResponse

	flushEvent := func() {
		payload := strings.TrimSpace(dataBuf.String())
		dataBuf.Reset()
		if payload == "" || payload == "[DONE]" {
			return
		}
		var rpcResp JSONRPCResponse
		if err := json.Unmarshal([]byte(payload), &rpcResp); err == nil && (rpcResp.ID != nil || rpcResp.Result != nil || rpcResp.Error != nil) {
			cp := rpcResp
			lastResp = &cp
		}
	}

	for _, rawLine := range lines {
		line := strings.TrimRight(rawLine, "\r")
		if strings.HasPrefix(line, "data:") {
			part := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
			if dataBuf.Len() > 0 {
				dataBuf.WriteByte('\n')
			}
			dataBuf.WriteString(part)
		} else if line == "" {
			flushEvent()
		}
	}
	flushEvent()

	if lastResp == nil {
		return nil, errors.New("no JSON-RPC response event found in SSE stream")
	}
	return lastResp, nil
}
