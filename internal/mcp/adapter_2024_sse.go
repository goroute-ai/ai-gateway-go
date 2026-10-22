package mcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/auth/upstream"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/security/network"
)

// HTTPSSEServer2024Transport adapts legacy MCP 2024 HTTP+SSE servers to the stateless gateway.
type HTTPSSEServer2024Transport struct {
	httpClient *http.Client
	mu         sync.RWMutex
	sessions   map[string]*sseSession // serverID -> session
}

type sseSession struct {
	serverID      string
	postEndpoint  string
	responseChans map[any]chan *JSONRPCResponse
	cancel        context.CancelFunc
	mu            sync.Mutex
}

// NewHTTPSSEServer2024Transport constructs a new legacy MCP 2024 SSE transport adapter.
func NewHTTPSSEServer2024Transport(netPolicy *network.Policy) *HTTPSSEServer2024Transport {
	client := network.NewHTTPClient(netPolicy)
	client.Timeout = 60 * time.Second
	return &HTTPSSEServer2024Transport{
		httpClient: client,
		sessions:   make(map[string]*sseSession),
	}
}

// RoundTrip executes an MCP call against a legacy 2024 HTTP+SSE upstream server.
func (t *HTTPSSEServer2024Transport) RoundTrip(
	ctx context.Context,
	server *domain.MCPServer,
	authStrategy upstream.Strategy,
	authCtx *upstream.UpstreamAuthContext,
	reqBytes []byte,
	clientHeaders http.Header,
) (*JSONRPCResponse, http.Header, error) {
	if server == nil {
		return nil, nil, errors.New("mcp 2024 sse: nil server")
	}

	var jsonRPCReq JSONRPCRequest
	if err := json.Unmarshal(reqBytes, &jsonRPCReq); err != nil {
		return nil, nil, fmt.Errorf("mcp 2024 sse: parse request: %w", err)
	}

	session, err := t.getOrCreateSession(ctx, server, authStrategy, authCtx)
	if err != nil {
		return nil, nil, fmt.Errorf("mcp 2024 sse: establish sse session: %w", err)
	}

	// Register response waiter for this request ID
	respCh := make(chan *JSONRPCResponse, 1)
	session.mu.Lock()
	session.responseChans[jsonRPCReq.ID] = respCh
	session.mu.Unlock()

	defer func() {
		session.mu.Lock()
		delete(session.responseChans, jsonRPCReq.ID)
		session.mu.Unlock()
	}()

	// POST the JSON-RPC request to the discovered SSE message endpoint
	postURL := session.postEndpoint
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, postURL, bytes.NewReader(reqBytes))
	if err != nil {
		return nil, nil, fmt.Errorf("mcp 2024 sse: create post request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json, text/plain, */*")

	if authStrategy != nil {
		if err := authStrategy.Apply(ctx, httpReq, authCtx); err != nil {
			return nil, nil, fmt.Errorf("mcp 2024 sse: apply auth: %w", err)
		}
	}

	postResp, err := t.httpClient.Do(httpReq)
	if err != nil {
		return nil, nil, fmt.Errorf("mcp 2024 sse: post message failed: %w", err)
	}
	defer postResp.Body.Close()

	// Some 2024 servers return the JSON-RPC response directly on the POST response
	postBody, _ := io.ReadAll(io.LimitReader(postResp.Body, 5*1024*1024))
	if len(postBody) > 0 {
		var syncResp JSONRPCResponse
		if err := json.Unmarshal(postBody, &syncResp); err == nil && (syncResp.Result != nil || syncResp.Error != nil) {
			return &syncResp, postResp.Header, nil
		}
	}

	// Otherwise, wait for the response to arrive over the SSE event stream
	select {
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	case asyncResp := <-respCh:
		return asyncResp, postResp.Header, nil
	case <-time.After(30 * time.Second):
		return nil, nil, errors.New("mcp 2024 sse: timeout waiting for response over sse stream")
	}
}

func (t *HTTPSSEServer2024Transport) getOrCreateSession(
	ctx context.Context,
	server *domain.MCPServer,
	authStrategy upstream.Strategy,
	authCtx *upstream.UpstreamAuthContext,
) (*sseSession, error) {
	t.mu.RLock()
	s, exists := t.sessions[server.ID]
	t.mu.RUnlock()

	if exists {
		return s, nil
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	// Double-check under write lock
	if s, exists := t.sessions[server.ID]; exists {
		return s, nil
	}

	// Initiate GET /sse stream connection
	sseURL := server.EndpointURL
	sessionCtx, cancel := context.WithCancel(context.Background())
	sseReq, err := http.NewRequestWithContext(sessionCtx, http.MethodGet, sseURL, nil)
	if err != nil {
		cancel()
		return nil, err
	}
	sseReq.Header.Set("Accept", "text/event-stream")

	if authStrategy != nil {
		_ = authStrategy.Apply(sessionCtx, sseReq, authCtx)
	}

	sseResp, err := t.httpClient.Do(sseReq)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to connect to sse stream at %s: %w", sseURL, err)
	}

	if sseResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(sseResp.Body, 1024))
		sseResp.Body.Close()
		cancel()
		return nil, fmt.Errorf("sse connect returned http %d: %s", sseResp.StatusCode, string(body))
	}

	sess := &sseSession{
		serverID:      server.ID,
		responseChans: make(map[any]chan *JSONRPCResponse),
		cancel:        cancel,
	}

	endpointDiscovered := make(chan string, 1)

	// Launch background SSE stream reader
	go func() {
		defer sseResp.Body.Close()
		defer cancel()

		scanner := bufio.NewScanner(sseResp.Body)
		buf := make([]byte, 64*1024)
		scanner.Buffer(buf, 2*1024*1024)
		var currentEvent string
		var dataBuffer strings.Builder

		for scanner.Scan() {
			select {
			case <-sessionCtx.Done():
				return
			default:
			}

			line := scanner.Text()
			if strings.HasPrefix(line, "event:") {
				currentEvent = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
			} else if strings.HasPrefix(line, "data:") {
				d := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
				dataBuffer.WriteString(d)
			} else if line == "" {
				// Dispatch completed SSE event
				payload := dataBuffer.String()
				dataBuffer.Reset()

				if currentEvent == "endpoint" && payload != "" {
					endpointURL := payload
					// If relative URL, resolve against sseURL
					if !strings.HasPrefix(endpointURL, "http://") && !strings.HasPrefix(endpointURL, "https://") {
						base, _ := url.Parse(sseURL)
						rel, _ := url.Parse(endpointURL)
						endpointURL = base.ResolveReference(rel).String()
					}
					sess.postEndpoint = endpointURL
					select {
					case endpointDiscovered <- endpointURL:
					default:
					}
				} else if payload != "" {
					// Check if this is a JSON-RPC response
					var rpcResp JSONRPCResponse
					if err := json.Unmarshal([]byte(payload), &rpcResp); err == nil && rpcResp.ID != nil {
						sess.mu.Lock()
						if ch, ok := sess.responseChans[rpcResp.ID]; ok {
							select {
							case ch <- &rpcResp:
							default:
							}
						}
						sess.mu.Unlock()
					}
				}
				currentEvent = ""
			}
		}
	}()

	// Wait for endpoint discovery event with timeout
	select {
	case <-time.After(10 * time.Second):
		cancel()
		return nil, errors.New("timeout waiting for initial 'endpoint' event from sse stream")
	case ep := <-endpointDiscovered:
		sess.postEndpoint = ep
	}

	t.sessions[server.ID] = sess
	return sess, nil
}

// Close gracefully closes all active SSE sessions.
func (t *HTTPSSEServer2024Transport) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, sess := range t.sessions {
		if sess.cancel != nil {
			sess.cancel()
		}
	}
	t.sessions = make(map[string]*sseSession)
	return nil
}
