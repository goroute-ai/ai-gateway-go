package mcp

import (
	"bytes"
	"container/list"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/auth/upstream"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/security/network"
)

const (
	maxOpenAPISpecCache = 512
	openAPISpecTTL      = 5 * time.Minute
)

// OpenAPIOperation maps an OpenAPI endpoint operation to an executable MCP tool.
type OpenAPIOperation struct {
	OperationID string         `json:"operation_id"`
	Method      string         `json:"method"`
	PathPattern string         `json:"path_pattern"`
	Summary     string         `json:"summary"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"input_schema"`
	PathParams  []string       `json:"path_params"`
	QueryParams []string       `json:"query_params"`
}

type openAPISpecKey struct {
	serverID      string
	configVersion int64
}

type openAPISpecEntry struct {
	key           openAPISpecKey
	ops           []OpenAPIOperation
	serverBaseURL string
	expiresAt     time.Time
}

// OpenAPITransport implements governed OpenAPI-to-MCP translation.
type OpenAPITransport struct {
	httpClient *http.Client
	specMu     sync.Mutex
	specCache  map[openAPISpecKey]*list.Element
	specLRU    *list.List
	maxSpecs   int
	specTTL    time.Duration
}

// NewOpenAPITransport creates a new OpenAPITransport.
func NewOpenAPITransport(netPolicy *network.Policy) *OpenAPITransport {
	client := network.NewHTTPClient(netPolicy)
	client.Timeout = 30 * time.Second
	return &OpenAPITransport{
		httpClient: client,
		specCache:  make(map[openAPISpecKey]*list.Element),
		specLRU:    list.New(),
		maxSpecs:   maxOpenAPISpecCache,
		specTTL:    openAPISpecTTL,
	}
}

func extractFirstOpenAPIServerURL(root map[string]any) string {
	serversRaw, ok := root["servers"].([]any)
	if !ok || len(serversRaw) == 0 {
		return ""
	}
	first, ok := serversRaw[0].(map[string]any)
	if !ok {
		return ""
	}
	u, _ := first["url"].(string)
	return strings.TrimSpace(u)
}

func parseOpenAPISpecWithServer(specJSON []byte) ([]OpenAPIOperation, string, error) {
	var root map[string]any
	if err := json.Unmarshal(specJSON, &root); err != nil {
		return nil, "", fmt.Errorf("openapi: parse spec json: %w", err)
	}
	ops, err := parseOpenAPIOperationsMap(root)
	if err != nil {
		return nil, "", err
	}
	return ops, extractFirstOpenAPIServerURL(root), nil
}

// ParseOpenAPISpec parses an OpenAPI 3.x document JSON into MCP tools.
func ParseOpenAPISpec(specJSON []byte) ([]OpenAPIOperation, error) {
	ops, _, err := parseOpenAPISpecWithServer(specJSON)
	return ops, err
}

func parseOpenAPIOperationsMap(root map[string]any) ([]OpenAPIOperation, error) {

	paths, ok := root["paths"].(map[string]any)
	if !ok {
		return nil, errors.New("openapi: missing or invalid 'paths' object in spec")
	}

	var operations []OpenAPIOperation

	for pathStr, pathObj := range paths {
		methodsMap, ok := pathObj.(map[string]any)
		if !ok {
			continue
		}

		for method, opObj := range methodsMap {
			mUpper := strings.ToUpper(method)
			if mUpper != "GET" && mUpper != "POST" && mUpper != "PUT" && mUpper != "DELETE" && mUpper != "PATCH" {
				continue
			}

			opMap, ok := opObj.(map[string]any)
			if !ok {
				continue
			}

			opID, _ := opMap["operationId"].(string)
			if opID == "" {
				// Synthesize unique operationId from method and path
				cleanedPath := strings.ReplaceAll(strings.Trim(pathStr, "/"), "/", "_")
				cleanedPath = strings.ReplaceAll(cleanedPath, "{", "")
				cleanedPath = strings.ReplaceAll(cleanedPath, "}", "")
				opID = strings.ToLower(mUpper) + "_" + cleanedPath
			}

			summary, _ := opMap["summary"].(string)
			desc, _ := opMap["description"].(string)
			if desc == "" {
				desc = summary
			}

			// Extract path & query parameters
			properties := make(map[string]any)
			pathParams, queryParams, requiredFields := extractOpenAPIParams(opMap, properties)

			// Request Body
			extractOpenAPIRequestBody(opMap, properties, &requiredFields)

			inputSchema := map[string]any{
				"type":       "object",
				"properties": properties,
			}
			if len(requiredFields) > 0 {
				inputSchema["required"] = requiredFields
			}

			operations = append(operations, OpenAPIOperation{
				OperationID: opID,
				Method:      mUpper,
				PathPattern: pathStr,
				Summary:     summary,
				Description: desc,
				InputSchema: inputSchema,
				PathParams:  pathParams,
				QueryParams: queryParams,
			})
		}
	}

	return operations, nil
}

func extractOpenAPIParams(opMap, properties map[string]any) ([]string, []string, []string) {
	var pathParams, queryParams, requiredFields []string
	paramsList, ok := opMap["parameters"].([]any)
	if !ok {
		return nil, nil, nil
	}
	for _, p := range paramsList {
		pMap, ok := p.(map[string]any)
		if !ok {
			continue
		}
		pName, _ := pMap["name"].(string)
		switch pIn, _ := pMap["in"].(string); pIn {
		case "path":
			pathParams = append(pathParams, pName)
		case "query":
			queryParams = append(queryParams, pName)
		}
		pSchema, _ := pMap["schema"].(map[string]any)
		if pSchema == nil {
			pSchema = map[string]any{"type": "string"}
		}
		properties[pName] = pSchema
		if req, _ := pMap["required"].(bool); req {
			requiredFields = append(requiredFields, pName)
		}
	}
	return pathParams, queryParams, requiredFields
}

func extractOpenAPIRequestBody(opMap, properties map[string]any, requiredFields *[]string) {
	reqBody, ok := opMap["requestBody"].(map[string]any)
	if !ok {
		return
	}
	content, ok := reqBody["content"].(map[string]any)
	if !ok {
		return
	}
	appJSON, ok := content["application/json"].(map[string]any)
	if !ok {
		return
	}
	if bSchema, ok := appJSON["schema"].(map[string]any); ok {
		properties["body"] = bSchema
		if req, _ := reqBody["required"].(bool); req {
			*requiredFields = append(*requiredFields, "body")
		}
	}
}

func (t *OpenAPITransport) getOperations(
	ctx context.Context,
	server *domain.MCPServer,
	authStrategy upstream.Strategy,
	authCtx *upstream.UpstreamAuthContext,
) ([]OpenAPIOperation, string, http.Header, error) {
	key := openAPISpecKey{serverID: server.ID, configVersion: server.ConfigVersion}
	now := time.Now()

	t.specMu.Lock()
	if elem, ok := t.specCache[key]; ok {
		entry := elem.Value.(*openAPISpecEntry)
		if now.Before(entry.expiresAt) {
			t.specLRU.MoveToFront(elem)
			ops := entry.ops
			srvBase := entry.serverBaseURL
			t.specMu.Unlock()
			return ops, srvBase, http.Header{}, nil
		}
		t.specLRU.Remove(elem)
		delete(t.specCache, key)
	}
	t.specMu.Unlock()

	specReq, err := http.NewRequestWithContext(ctx, http.MethodGet, server.EndpointURL, nil)
	if err != nil {
		return nil, "", nil, err
	}
	specReq.Header.Set("Accept", "application/json")
	if authStrategy != nil {
		if err := authStrategy.Apply(ctx, specReq, authCtx); err != nil {
			return nil, "", nil, fmt.Errorf("openapi: apply auth: %w", err)
		}
	}

	resp, err := t.httpClient.Do(specReq)
	if err != nil {
		return nil, "", nil, fmt.Errorf("openapi: fetch spec: %w", err)
	}
	defer resp.Body.Close()

	specBody, err := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024))
	if err != nil {
		return nil, "", nil, err
	}

	ops, specServerURL, err := parseOpenAPISpecWithServer(specBody)
	if err != nil {
		return nil, "", nil, err
	}

	t.specMu.Lock()
	if elem, ok := t.specCache[key]; ok {
		entry := elem.Value.(*openAPISpecEntry)
		entry.ops = ops
		entry.serverBaseURL = specServerURL
		entry.expiresAt = time.Now().Add(t.specTTL)
		t.specLRU.MoveToFront(elem)
	} else {
		for t.specLRU.Len() >= t.maxSpecs {
			tail := t.specLRU.Back()
			if tail == nil {
				break
			}
			tailEntry := tail.Value.(*openAPISpecEntry)
			t.specLRU.Remove(tail)
			delete(t.specCache, tailEntry.key)
		}
		elem := t.specLRU.PushFront(&openAPISpecEntry{
			key:           key,
			ops:           ops,
			serverBaseURL: specServerURL,
			expiresAt:     time.Now().Add(t.specTTL),
		})
		t.specCache[key] = elem
	}
	t.specMu.Unlock()

	return ops, specServerURL, resp.Header, nil
}

func fallbackOpenAPIBaseURL(endpointURL string) string {
	baseURL := strings.TrimRight(endpointURL, "/")
	if strings.HasSuffix(baseURL, ".json") || strings.HasSuffix(baseURL, ".yaml") {
		lastSlash := strings.LastIndex(baseURL, "/")
		if lastSlash > 0 {
			baseURL = baseURL[:lastSlash]
		}
	}
	return baseURL
}

// resolveOpenAPIBaseURL honors relative and same-origin OpenAPI servers[0].url entries
// while refusing cross-origin host overrides to prevent remote-spec SSRF redirection.
func resolveOpenAPIBaseURL(endpointURL, specServerURL string) (baseURL string, crossOriginIgnored bool) {
	fallback := fallbackOpenAPIBaseURL(endpointURL)
	trimmedSpec := strings.TrimSpace(specServerURL)
	if trimmedSpec == "" {
		return fallback, false
	}

	epParsed, epErr := url.Parse(endpointURL)
	srvParsed, srvErr := url.Parse(trimmedSpec)
	if epErr != nil || srvErr != nil || epParsed.Host == "" {
		return fallback, false
	}

	// Relative path (e.g. "/v2" or "v2") stays pinned to endpointURL's scheme://host.
	if srvParsed.Scheme == "" && srvParsed.Host == "" {
		relPath := "/" + strings.TrimLeft(srvParsed.Path, "/")
		resolved := &url.URL{
			Scheme: epParsed.Scheme,
			Host:   epParsed.Host,
			Path:   strings.TrimRight(relPath, "/"),
		}
		return strings.TrimRight(resolved.String(), "/"), false
	}

	// Reject cross-origin host or scheme redirects embedded inside untrusted OpenAPI specs.
	if !strings.EqualFold(srvParsed.Scheme, epParsed.Scheme) || !strings.EqualFold(srvParsed.Host, epParsed.Host) {
		return fallback, true
	}

	return strings.TrimRight(srvParsed.String(), "/"), false
}

func (t *OpenAPITransport) RoundTrip(
	ctx context.Context,
	server *domain.MCPServer,
	authStrategy upstream.Strategy,
	authCtx *upstream.UpstreamAuthContext,
	reqBytes []byte,
	clientHeaders http.Header,
) (*JSONRPCResponse, http.Header, error) {
	if server == nil {
		return nil, nil, errors.New("openapi: nil server")
	}

	var jsonRPCReq JSONRPCRequest
	if err := json.Unmarshal(reqBytes, &jsonRPCReq); err != nil {
		return nil, nil, fmt.Errorf("openapi: parse json-rpc: %w", err)
	}

	switch jsonRPCReq.Method {
	case "server/discover":
		return &JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      jsonRPCReq.ID,
			Result: map[string]any{
				"resultType":        "complete",
				"cacheScope":        "private",
				"ttlMs":             60000,
				"supportedVersions": []string{domain.MCPProtocolVersion20260728},
				"capabilities": map[string]any{
					"tools": map[string]any{"listChanged": false},
				},
			},
		}, nil, nil
	case "tools/list":
		ops, _, respHeaders, err := t.getOperations(ctx, server, authStrategy, authCtx)
		if err != nil {
			return nil, nil, err
		}

		var tools []map[string]any
		for _, op := range ops {
			tools = append(tools, map[string]any{
				"name":        op.OperationID,
				"description": op.Description,
				"inputSchema": op.InputSchema,
			})
		}

		return &JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      jsonRPCReq.ID,
			Result: map[string]any{
				"tools": tools,
			},
		}, respHeaders, nil

	case "tools/call":
		var params map[string]any
		_ = json.Unmarshal(jsonRPCReq.Params, &params)

		toolName, _ := params["name"].(string)
		args, _ := params["arguments"].(map[string]any)
		if args == nil {
			args = make(map[string]any)
		}

		ops, specServerURL, _, err := t.getOperations(ctx, server, authStrategy, authCtx)
		if err != nil {
			return nil, nil, err
		}

		var targetOp *OpenAPIOperation
		for _, op := range ops {
			if op.OperationID == toolName {
				targetOp = &op
				break
			}
		}

		if targetOp == nil {
			return &JSONRPCResponse{
				JSONRPC: "2.0",
				ID:      jsonRPCReq.ID,
				Error: &JSONRPCError{
					Code:    CodeMethodNotFound,
					Message: fmt.Sprintf("operation %q not found in openapi spec", toolName),
				},
			}, nil, nil
		}

		baseURL, crossOriginIgnored := resolveOpenAPIBaseURL(server.EndpointURL, specServerURL)
		if crossOriginIgnored {
			slog.Warn(
				"openapi transport ignored cross-origin servers[0].url override",
				slog.String("server_id", server.ID),
				slog.String("spec_server_url", specServerURL),
				slog.String("endpoint_url", server.EndpointURL),
			)
		}

		resolvedPath := targetOp.PathPattern
		for _, p := range targetOp.PathParams {
			val, ok := args[p]
			if !ok {
				return nil, nil, fmt.Errorf("openapi: missing required path parameter %q", p)
			}
			resolvedPath = strings.ReplaceAll(resolvedPath, "{"+p+"}", url.PathEscape(fmt.Sprint(val)))
		}

		targetURL := baseURL + resolvedPath

		// Append query parameters
		if len(targetOp.QueryParams) > 0 {
			qVals := url.Values{}
			for _, q := range targetOp.QueryParams {
				if val, ok := args[q]; ok {
					qVals.Set(q, fmt.Sprint(val))
				}
			}
			if len(qVals) > 0 {
				if strings.Contains(targetURL, "?") {
					targetURL += "&" + qVals.Encode()
				} else {
					targetURL += "?" + qVals.Encode()
				}
			}
		}

		// Body
		var bodyReader io.Reader
		if bodyArg, hasBody := args["body"]; hasBody {
			bBytes, _ := json.Marshal(bodyArg)
			bodyReader = bytes.NewReader(bBytes)
		} else if targetOp.Method == "POST" || targetOp.Method == "PUT" || targetOp.Method == "PATCH" {
			// Extract remaining non-path non-query arguments as body
			bodyFields := make(map[string]any)
			pathParamSet := make(map[string]bool)
			for _, p := range targetOp.PathParams {
				pathParamSet[p] = true
			}
			for _, q := range targetOp.QueryParams {
				pathParamSet[q] = true
			}
			for k, v := range args {
				if !pathParamSet[k] {
					bodyFields[k] = v
				}
			}
			if len(bodyFields) > 0 {
				bBytes, _ := json.Marshal(bodyFields)
				bodyReader = bytes.NewReader(bBytes)
			}
		}

		httpReq, err := http.NewRequestWithContext(ctx, targetOp.Method, targetURL, bodyReader)
		if err != nil {
			return nil, nil, fmt.Errorf("openapi: create upstream request: %w", err)
		}

		if bodyReader != nil {
			httpReq.Header.Set("Content-Type", "application/json")
		}
		httpReq.Header.Set("Accept", "application/json")

		// Apply upstream authentication
		if authStrategy != nil {
			if err := authStrategy.Apply(ctx, httpReq, authCtx); err != nil {
				return nil, nil, fmt.Errorf("openapi: apply auth: %w", err)
			}
		}

		callResp, err := t.httpClient.Do(httpReq)
		if err != nil {
			return nil, nil, fmt.Errorf("openapi: dispatch to upstream: %w", err)
		}
		defer callResp.Body.Close()

		respBytes, err := io.ReadAll(io.LimitReader(callResp.Body, 10*1024*1024))
		if err != nil {
			return nil, nil, fmt.Errorf("openapi: read upstream response: %w", err)
		}

		isErr := callResp.StatusCode >= 400

		return &JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      jsonRPCReq.ID,
			Result: map[string]any{
				"content": []map[string]any{
					{
						"type": "text",
						"text": string(respBytes),
					},
				},
				"isError": isErr,
				"_meta": map[string]any{
					"http_status": callResp.StatusCode,
				},
			},
		}, callResp.Header, nil

	default:
		return &JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      jsonRPCReq.ID,
			Error: &JSONRPCError{
				Code:    CodeMethodNotFound,
				Message: fmt.Sprintf("unsupported method %q for openapi transport", jsonRPCReq.Method),
			},
		}, nil, nil
	}
}
