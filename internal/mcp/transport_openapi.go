package mcp

import (
	"bytes"
	"container/list"
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
	key       openAPISpecKey
	ops       []OpenAPIOperation
	expiresAt time.Time
}

// OpenAPITransport implements governed OpenAPI-to-MCP translation.
type OpenAPITransport struct {
	httpClient *http.Client
	netPolicy  *network.Policy
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
		netPolicy:  netPolicy,
		specCache:  make(map[openAPISpecKey]*list.Element),
		specLRU:    list.New(),
		maxSpecs:   maxOpenAPISpecCache,
		specTTL:    openAPISpecTTL,
	}
}

// ParseOpenAPISpec parses an OpenAPI 3.x document JSON into MCP tools.
func ParseOpenAPISpec(specJSON []byte) ([]OpenAPIOperation, error) {
	var root map[string]any
	if err := json.Unmarshal(specJSON, &root); err != nil {
		return nil, fmt.Errorf("openapi: parse spec json: %w", err)
	}

	paths, ok := root["paths"].(map[string]any)
	if !ok {
		return nil, errors.New("openapi: missing or invalid 'paths' object in spec")
	}

	var operations []OpenAPIOperation

	for pathStr, pathObj := range paths {
		if !isSafeOpenAPIPath(pathStr) {
			continue
		}
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
			var pathParams []string
			var queryParams []string
			properties := make(map[string]any)
			var requiredFields []string

			if paramsList, ok := opMap["parameters"].([]any); ok {
				for _, p := range paramsList {
					pMap, ok := p.(map[string]any)
					if !ok {
						continue
					}
					pName, _ := pMap["name"].(string)
					pIn, _ := pMap["in"].(string)
					pReq, _ := pMap["required"].(bool)

					if pIn == "path" {
						pathParams = append(pathParams, pName)
					} else if pIn == "query" {
						queryParams = append(queryParams, pName)
					}

					pSchema, _ := pMap["schema"].(map[string]any)
					if pSchema == nil {
						pSchema = map[string]any{"type": "string"}
					}
					properties[pName] = pSchema
					if pReq {
						requiredFields = append(requiredFields, pName)
					}
				}
			}

			// Request Body
			if reqBody, ok := opMap["requestBody"].(map[string]any); ok {
				if content, ok := reqBody["content"].(map[string]any); ok {
					if appJSON, ok := content["application/json"].(map[string]any); ok {
						if bSchema, ok := appJSON["schema"].(map[string]any); ok {
							properties["body"] = bSchema
							if req, _ := reqBody["required"].(bool); req {
								requiredFields = append(requiredFields, "body")
							}
						}
					}
				}
			}

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

func (t *OpenAPITransport) getOperations(
	ctx context.Context,
	server *domain.MCPServer,
	authStrategy upstream.Strategy,
	authCtx *upstream.UpstreamAuthContext,
) ([]OpenAPIOperation, http.Header, error) {
	key := openAPISpecKey{serverID: server.ID, configVersion: server.ConfigVersion}
	now := time.Now()

	t.specMu.Lock()
	if elem, ok := t.specCache[key]; ok {
		entry := elem.Value.(*openAPISpecEntry)
		if now.Before(entry.expiresAt) {
			t.specLRU.MoveToFront(elem)
			ops := entry.ops
			t.specMu.Unlock()
			return ops, http.Header{}, nil
		}
		t.specLRU.Remove(elem)
		delete(t.specCache, key)
	}
	t.specMu.Unlock()

	parsedEndpoint, err := url.Parse(server.EndpointURL)
	if err != nil || (parsedEndpoint.Scheme != "http" && parsedEndpoint.Scheme != "https") || parsedEndpoint.Host == "" {
		return nil, nil, errors.New("openapi: invalid server endpoint URL")
	}
	if t.netPolicy != nil {
		if err := t.netPolicy.ValidateURL(parsedEndpoint); err != nil {
			return nil, nil, fmt.Errorf("openapi: blocked endpoint URL: %w", err)
		}
	}

	specReq, err := http.NewRequestWithContext(ctx, http.MethodGet, parsedEndpoint.String(), nil)
	if err != nil {
		return nil, nil, err
	}
	specReq.Header.Set("Accept", "application/json")
	if authStrategy != nil {
		if err := authStrategy.Apply(ctx, specReq, authCtx); err != nil {
			return nil, nil, fmt.Errorf("openapi: apply auth: %w", err)
		}
	}

	resp, err := t.httpClient.Do(specReq)
	if err != nil {
		return nil, nil, fmt.Errorf("openapi: fetch spec: %w", err)
	}
	defer resp.Body.Close()

	specBody, err := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024))
	if err != nil {
		return nil, nil, err
	}

	ops, err := ParseOpenAPISpec(specBody)
	if err != nil {
		return nil, nil, err
	}

	t.specMu.Lock()
	if elem, ok := t.specCache[key]; ok {
		entry := elem.Value.(*openAPISpecEntry)
		entry.ops = ops
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
			key:       key,
			ops:       ops,
			expiresAt: time.Now().Add(t.specTTL),
		})
		t.specCache[key] = elem
	}
	t.specMu.Unlock()

	return ops, resp.Header, nil
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
		ops, respHeaders, err := t.getOperations(ctx, server, authStrategy, authCtx)
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

		ops, _, err := t.getOperations(ctx, server, authStrategy, authCtx)
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

		httpReq, err := buildSafeOpenAPIRequest(ctx, server.EndpointURL, targetOp, args, bodyReader, t.netPolicy)
		if err != nil {
			return nil, nil, err
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

func isSafeOpenAPIPath(p string) bool {
	if !strings.HasPrefix(p, "/") || strings.HasPrefix(p, "//") {
		return false
	}
	if strings.ContainsAny(p, "\\\r\n\x00?#") {
		return false
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == "." || seg == ".." {
			return false
		}
	}
	return true
}

func buildSafeOpenAPIRequest(
	ctx context.Context,
	endpointURL string,
	targetOp *OpenAPIOperation,
	args map[string]any,
	bodyReader io.Reader,
	netPolicy *network.Policy,
) (*http.Request, error) {
	baseURL := strings.TrimRight(endpointURL, "/")
	if strings.HasSuffix(baseURL, ".json") || strings.HasSuffix(baseURL, ".yaml") {
		if lastSlash := strings.LastIndex(baseURL, "/"); lastSlash > 0 {
			baseURL = baseURL[:lastSlash]
		}
	}

	baseParsed, err := url.Parse(baseURL)
	if err != nil || (baseParsed.Scheme != "http" && baseParsed.Scheme != "https") || baseParsed.Host == "" || baseParsed.User != nil {
		return nil, errors.New("openapi: invalid server base URL")
	}
	if !isSafeOpenAPIPath(targetOp.PathPattern) {
		return nil, errors.New("openapi: unsafe operation path pattern")
	}

	resolvedRawPath := targetOp.PathPattern
	resolvedEscapedPath := targetOp.PathPattern
	for _, p := range targetOp.PathParams {
		val, ok := args[p]
		if !ok {
			return nil, fmt.Errorf("openapi: missing required path parameter %q", p)
		}
		valStr := fmt.Sprint(val)
		if valStr == "" || valStr == "." || valStr == ".." || strings.Contains(valStr, "..") || strings.ContainsAny(valStr, "/\\?#\r\n\x00") {
			return nil, fmt.Errorf("openapi: invalid path parameter %q", p)
		}
		resolvedRawPath = strings.ReplaceAll(resolvedRawPath, "{"+p+"}", valStr)
		resolvedEscapedPath = strings.ReplaceAll(resolvedEscapedPath, "{"+p+"}", url.PathEscape(valStr))
	}
	if !isSafeOpenAPIPath(resolvedRawPath) {
		return nil, errors.New("openapi: invalid resolved request path")
	}

	qVals := url.Values{}
	for _, q := range targetOp.QueryParams {
		if val, ok := args[q]; ok {
			qVals.Set(q, fmt.Sprint(val))
		}
	}

	// Build request strictly from validated base scheme+host before attaching sanitized path/query.
	baseOrigin := (&url.URL{Scheme: baseParsed.Scheme, Host: baseParsed.Host}).String()
	httpReq, err := http.NewRequestWithContext(ctx, targetOp.Method, baseOrigin, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("openapi: create upstream request: %w", err)
	}
	httpReq.URL.Path = strings.TrimRight(baseParsed.Path, "/") + resolvedRawPath
	if resolvedEscapedPath != resolvedRawPath || baseParsed.RawPath != "" {
		httpReq.URL.RawPath = strings.TrimRight(baseParsed.EscapedPath(), "/") + resolvedEscapedPath
	}
	if len(qVals) > 0 {
		httpReq.URL.RawQuery = qVals.Encode()
	}

	if netPolicy != nil {
		if err := netPolicy.ValidateURL(httpReq.URL); err != nil {
			return nil, fmt.Errorf("openapi: blocked target URL: %w", err)
		}
	}
	return httpReq, nil
}
