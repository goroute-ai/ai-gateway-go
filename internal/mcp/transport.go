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
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/auth/upstream"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/observability"
	"github.com/goroute-ai/ai-gateway-go/internal/security/network"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
)

var (
	ErrStdioDisabled = errors.New("mcp: stdio subprocess transport is disabled (OS-level sandboxing BL-02 required)")
)

// MCPTransport defines the round-trip interface for dispatching requests to upstream MCP servers.
type MCPTransport interface {
	RoundTrip(ctx context.Context, server *domain.MCPServer, authStrategy upstream.Strategy, authCtx *upstream.UpstreamAuthContext, reqBytes []byte, clientHeaders http.Header) (*JSONRPCResponse, http.Header, error)
}

// StreamableHTTP2026Transport implements MCP 2026-07-28 stateless Streamable HTTP transport.
type StreamableHTTP2026Transport struct {
	httpClient *http.Client
}

// NewStreamableHTTP2026Transport creates a new StreamableHTTP2026Transport with SSRF network security controls.
func NewStreamableHTTP2026Transport(netPolicy *network.Policy) *StreamableHTTP2026Transport {
	return &StreamableHTTP2026Transport{
		httpClient: network.NewHTTPClient(netPolicy),
	}
}

func (t *StreamableHTTP2026Transport) RoundTrip(
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

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, server.EndpointURL, bytes.NewReader(reqBytes))
	if err != nil {
		return nil, nil, fmt.Errorf("create mcp request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json, text/event-stream")

	// Inject W3C distributed tracing context
	observability.InjectTraceHeaders(ctx, httpReq)

	// Forward mirrored Mcp-* headers from client
	for k, v := range clientHeaders {
		if strings.HasPrefix(strings.ToLower(k), "mcp-") {
			httpReq.Header[k] = v
		}
	}

	// Apply upstream authentication strategy
	if authStrategy != nil {
		if err := authStrategy.Apply(ctx, httpReq, authCtx); err != nil {
			return nil, nil, fmt.Errorf("apply upstream auth: %w", err)
		}
	}

	resp, err := t.httpClient.Do(httpReq)
	if err != nil {
		return nil, nil, fmt.Errorf("upstream mcp request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
	if err != nil {
		return nil, nil, fmt.Errorf("read mcp response: %w", err)
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

	return &jsonResp, resp.Header, nil
}

// TransportDispatcher routes MCP calls to the appropriate transport version.
type TransportDispatcher struct {
	transport2026    *StreamableHTTP2026Transport
	adapter2025      *StreamableHTTP2025Adapter
	adapter2024      *HTTPSSEServer2024Transport
	transportOpenAPI *OpenAPITransport
	transportStdio   *StdioTransport
	allowStdio       bool
}

// NewTransportDispatcher creates a new TransportDispatcher.
func NewTransportDispatcher(netPolicy *network.Policy, redisFabric *storage.RedisFabric, allowStdio bool) *TransportDispatcher {
	return &TransportDispatcher{
		transport2026:    NewStreamableHTTP2026Transport(netPolicy),
		adapter2025:      NewStreamableHTTP2025Adapter(netPolicy, redisFabric),
		adapter2024:      NewHTTPSSEServer2024Transport(netPolicy),
		transportOpenAPI: NewOpenAPITransport(netPolicy),
		transportStdio:   NewStdioTransport(StdioSecurityPolicy{AllowedBinaries: []string{"*"}, DefaultTimeout: 30 * time.Second}),
		allowStdio:       allowStdio,
	}
}

// Dispatch executes the round-trip through the corresponding transport adapter.
func (d *TransportDispatcher) Dispatch(
	ctx context.Context,
	server *domain.MCPServer,
	authStrategy upstream.Strategy,
	authCtx *upstream.UpstreamAuthContext,
	reqBytes []byte,
	clientHeaders http.Header,
) (*JSONRPCResponse, http.Header, error) {
	if server.TransportType == domain.MCPTransportStdio {
		if !d.allowStdio {
			return nil, nil, ErrStdioDisabled
		}
		return d.transportStdio.RoundTrip(ctx, server, authStrategy, authCtx, reqBytes, clientHeaders)
	}

	if server.TransportType == "openapi" {
		return d.transportOpenAPI.RoundTrip(ctx, server, authStrategy, authCtx, reqBytes, clientHeaders)
	}

	if server.ProtocolVersion == "2024-11-05" || server.TransportType == "http_sse_2024" {
		return d.adapter2024.RoundTrip(ctx, server, authStrategy, authCtx, reqBytes, clientHeaders)
	}

	if server.ProtocolVersion == domain.MCPProtocolVersion2025 {
		return d.adapter2025.RoundTrip(ctx, server, authStrategy, authCtx, reqBytes, clientHeaders)
	}

	// Default to primary MCP 2026-07-28 stateless transport
	return d.transport2026.RoundTrip(ctx, server, authStrategy, authCtx, reqBytes, clientHeaders)
}
