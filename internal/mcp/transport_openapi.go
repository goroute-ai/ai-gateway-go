package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/auth/upstream"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/security/network"
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

// OpenAPITransport implements governed OpenAPI-to-MCP translation.
type OpenAPITransport struct {
	httpClient *http.Client
}

// NewOpenAPITransport creates a new OpenAPITransport.
func NewOpenAPITransport(netPolicy *network.Policy) *OpenAPITransport {
	client := network.NewHTTPClient(netPolicy)
	client.Timeout = 30 * time.Second
	return &OpenAPITransport{
		httpClient: client,
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
	case "tools/list":
		// Fetch OpenAPI spec from server endpoint
		specReq, err := http.NewRequestWithContext(ctx, http.MethodGet, server.EndpointURL, nil)
		if err != nil {
			return nil, nil, err
		}
		specReq.Header.Set("Accept", "application/json")
		if authStrategy != nil {
			_ = authStrategy.Apply(ctx, specReq, authCtx)
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
		}, resp.Header, nil

	case "tools/call":
		var params map[string]any
		_ = json.Unmarshal(jsonRPCReq.Params, &params)

		toolName, _ := params["name"].(string)
		args, _ := params["arguments"].(map[string]any)
		if args == nil {
			args = make(map[string]any)
		}

		// First, discover operations to locate target endpoint
		specReq, err := http.NewRequestWithContext(ctx, http.MethodGet, server.EndpointURL, nil)
		if err != nil {
			return nil, nil, err
		}
		specReq.Header.Set("Accept", "application/json")
		if authStrategy != nil {
			_ = authStrategy.Apply(ctx, specReq, authCtx)
		}

		specResp, err := t.httpClient.Do(specReq)
		if err != nil {
			return nil, nil, fmt.Errorf("openapi: fetch spec: %w", err)
		}
		defer specResp.Body.Close()

		specBody, _ := io.ReadAll(io.LimitReader(specResp.Body, 5*1024*1024))
		ops, err := ParseOpenAPISpec(specBody)
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

		// Construct target URL with path parameters
		baseURL := strings.TrimRight(server.EndpointURL, "/")
		// If EndpointURL points to /openapi.json, strip filename to get base service path
		if strings.HasSuffix(baseURL, ".json") || strings.HasSuffix(baseURL, ".yaml") {
			lastSlash := strings.LastIndex(baseURL, "/")
			if lastSlash > 0 {
				baseURL = baseURL[:lastSlash]
			}
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
