package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
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

	normalizedBody, method, targetName := prepare2026OutboundRequest(reqBytes)

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, server.EndpointURL, bytes.NewReader(normalizedBody))
	if err != nil {
		return nil, nil, fmt.Errorf("create mcp request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json, text/event-stream")

	// Inject W3C distributed tracing context.
	observability.InjectTraceHeaders(ctx, httpReq)

	// Forward mirrored Mcp-* headers from client before setting canonical 2026-07-28 headers.
	for k, v := range clientHeaders {
		if strings.HasPrefix(strings.ToLower(k), "mcp-") {
			httpReq.Header[k] = v
		}
	}
	httpReq.Header.Set("MCP-Protocol-Version", domain.MCPProtocolVersion20260728)
	if method != "" {
		httpReq.Header.Set("Mcp-Method", method)
	}
	if targetName != "" {
		httpReq.Header.Set("Mcp-Name", EncodeBase64Sentinel(targetName))
	}

	// Apply upstream authentication strategy.
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

	jsonResp, rpcErr := parseMCPHTTPResponse(resp)
	if rpcErr != nil {
		return nil, resp.Header, rpcErr
	}
	return jsonResp, resp.Header, nil
}

// prepare2026OutboundRequest ensures outgoing requests conform to MCP 2026-07-28 params._meta rules
// and extracts the method and target name/URI for mirrored HTTP routing headers.
func prepare2026OutboundRequest(reqBytes []byte) ([]byte, string, string) {
	var msg map[string]any
	dec := json.NewDecoder(bytes.NewReader(reqBytes))
	dec.UseNumber()
	if err := dec.Decode(&msg); err != nil {
		return reqBytes, "", ""
	}
	method, _ := msg["method"].(string)

	params, ok := msg["params"].(map[string]any)
	if !ok || params == nil {
		params = make(map[string]any)
		msg["params"] = params
	}
	targetName := ""
	if name, ok := params["name"].(string); ok && name != "" {
		targetName = name
	} else if uri, ok := params["uri"].(string); ok && uri != "" {
		targetName = uri
	}

	meta, ok := params["_meta"].(map[string]any)
	if !ok || meta == nil {
		meta = make(map[string]any)
		params["_meta"] = meta
	}
	if _, exists := meta["io.modelcontextprotocol/protocolVersion"]; !exists {
		meta["io.modelcontextprotocol/protocolVersion"] = domain.MCPProtocolVersion20260728
	}
	if _, exists := meta["io.modelcontextprotocol/clientCapabilities"]; !exists {
		meta["io.modelcontextprotocol/clientCapabilities"] = map[string]any{}
	}

	encoded, err := json.Marshal(msg)
	if err != nil {
		return reqBytes, method, targetName
	}
	return encoded, method, targetName
}

// TransportDispatcher routes MCP calls to the appropriate protocol-release transport driver.
type TransportDispatcher struct {
	transport2026     *StreamableHTTP2026Transport
	statefulTransport *StatefulStreamableTransport
	adapter2024       *HTTPSSEServer2024Transport
	transportOpenAPI  *OpenAPITransport
	transportStdio    *StdioTransport
	allowStdio        bool
}

// NewTransportDispatcher creates a new TransportDispatcher covering all official MCP releases.
func NewTransportDispatcher(netPolicy *network.Policy, redisFabric *storage.RedisFabric, allowStdio bool) *TransportDispatcher {
	return &TransportDispatcher{
		transport2026:     NewStreamableHTTP2026Transport(netPolicy),
		statefulTransport: NewStatefulStreamableTransport(netPolicy, redisFabric),
		adapter2024:       NewHTTPSSEServer2024Transport(netPolicy),
		transportOpenAPI:  NewOpenAPITransport(netPolicy),
		transportStdio:    NewStdioTransport(StdioSecurityPolicy{AllowedBinaries: []string{}, DefaultTimeout: 30 * time.Second}),
		allowStdio:        allowStdio,
	}
}

// SetStdioPolicy updates the stdio subprocess security policy on the dispatcher.
func (d *TransportDispatcher) SetStdioPolicy(policy StdioSecurityPolicy) {
	d.transportStdio = NewStdioTransport(policy)
}

// Dispatch executes the round-trip through the upstream server's configured MCP specification driver.
func (d *TransportDispatcher) Dispatch(
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

	if server.TransportType == domain.MCPTransportStdio {
		if !d.allowStdio {
			return nil, nil, ErrStdioDisabled
		}
		return d.transportStdio.RoundTrip(ctx, server, authStrategy, authCtx, reqBytes, clientHeaders)
	}

	if server.TransportType == domain.MCPTransportOpenAPI {
		return d.transportOpenAPI.RoundTrip(ctx, server, authStrategy, authCtx, reqBytes, clientHeaders)
	}

	if server.ProtocolVersion == domain.MCPProtocolVersion20241105 || server.TransportType == domain.MCPTransportHTTPSSE2024 {
		return d.adapter2024.RoundTrip(ctx, server, authStrategy, authCtx, reqBytes, clientHeaders)
	}

	switch server.ProtocolVersion {
	case domain.MCPProtocolVersion20250326, domain.MCPProtocolVersion20250618, domain.MCPProtocolVersion20251125:
		return d.statefulTransport.RoundTrip(ctx, server, authStrategy, authCtx, reqBytes, clientHeaders)
	case "", domain.MCPProtocolVersion20260728:
		return d.transport2026.RoundTrip(ctx, server, authStrategy, authCtx, reqBytes, clientHeaders)
	default:
		return nil, nil, fmt.Errorf("mcp: unsupported server protocol version %q", server.ProtocolVersion)
	}
}
