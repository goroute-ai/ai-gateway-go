package server_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/server"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
)

func TestToolLoop_SyncAndStreamIntegration(t *testing.T) {
	ctx := context.Background()

	// 1. Upstream MCP server implementing calculator_add
	mcpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		var rpcReq map[string]any
		_ = json.NewDecoder(r.Body).Decode(&rpcReq)

		method, _ := rpcReq["method"].(string)
		id := rpcReq["id"]

		switch method {
		case "tools/list":
			json.NewEncoder(w).Encode(map[string]any{
				"jsonrpc": "2.0",
				"id":      id,
				"result": map[string]any{
					"tools": []map[string]any{
						{
							"name":        "calculator_add",
							"description": "Adds two numbers",
							"inputSchema": map[string]any{
								"type": "object",
								"properties": map[string]any{
									"a": map[string]any{"type": "number"},
									"b": map[string]any{"type": "number"},
								},
								"required": []string{"a", "b"},
							},
						},
					},
				},
			})
		case "tools/call":
			params, _ := rpcReq["params"].(map[string]any)
			args, _ := params["arguments"].(map[string]any)
			a, _ := args["a"].(float64)
			b, _ := args["b"].(float64)
			sum := a + b
			json.NewEncoder(w).Encode(map[string]any{
				"jsonrpc": "2.0",
				"id":      id,
				"result": map[string]any{
					"content": []map[string]any{
						{"type": "text", "text": fmt.Sprintf(`{"sum": %g}`, sum)},
					},
					"isError": false,
				},
			})
		default:
			json.NewEncoder(w).Encode(map[string]any{
				"jsonrpc": "2.0",
				"id":      id,
				"error":   map[string]any{"code": -32601, "message": "method not found"},
			})
		}
	}))
	defer mcpServer.Close()

	// 2. Upstream LLM Server simulating multi-turn tool calling
	var modelTurnCount atomic.Int32
	llmServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		turn := modelTurnCount.Add(1)
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)

		isStream, _ := body["stream"].(bool)
		w.Header().Set("Content-Type", "application/json")

		if turn == 1 {
			// First turn: model requests calculator_add tool call
			if isStream {
				w.Header().Set("Content-Type", "text/event-stream")
				flusher, _ := w.(http.Flusher)
				// Emit tool call chunk
				chunk := map[string]any{
					"id":      "chatcmpl_tc_1",
					"object":  "chat.completion.chunk",
					"created": time.Now().Unix(),
					"choices": []map[string]any{
						{
							"index": 0,
							"delta": map[string]any{
								"role": "assistant",
								"tool_calls": []map[string]any{
									{
										"index": 0,
										"id":    "call_calc_01",
										"type":  "function",
										"function": map[string]any{
											"name":      "calculator_add",
											"arguments": `{"a": 20, "b": 30}`,
										},
									},
								},
							},
							"finish_reason": "tool_calls",
						},
					},
				}
				data, _ := json.Marshal(chunk)
				fmt.Fprintf(w, "data: %s\n\ndata: [DONE]\n\n", string(data))
				if flusher != nil {
					flusher.Flush()
				}
				return
			}

			resp := map[string]any{
				"id":      "chatcmpl_tc_1",
				"object":  "chat.completion",
				"created": time.Now().Unix(),
				"choices": []map[string]any{
					{
						"index": 0,
						"message": map[string]any{
							"role": "assistant",
							"tool_calls": []map[string]any{
								{
									"id":   "call_calc_01",
									"type": "function",
									"function": map[string]any{
										"name":      "calculator_add",
										"arguments": `{"a": 20, "b": 30}`,
									},
								},
							},
						},
						"finish_reason": "tool_calls",
					},
				},
				"usage": map[string]any{
					"prompt_tokens":     15,
					"completion_tokens": 10,
					"total_tokens":      25,
				},
			}
			json.NewEncoder(w).Encode(resp)
			return
		}

		// Second turn: model receives tool output and returns final answer
		if isStream {
			w.Header().Set("Content-Type", "text/event-stream")
			flusher, _ := w.(http.Flusher)
			chunk := map[string]any{
				"id":      "chatcmpl_final_2",
				"object":  "chat.completion.chunk",
				"created": time.Now().Unix(),
				"choices": []map[string]any{
					{
						"index": 0,
						"delta": map[string]any{
							"role":    "assistant",
							"content": "The sum of 20 and 30 is 50.",
						},
						"finish_reason": "stop",
					},
				},
				"usage": map[string]any{
					"prompt_tokens":     35,
					"completion_tokens": 12,
					"total_tokens":      47,
				},
			}
			data, _ := json.Marshal(chunk)
			fmt.Fprintf(w, "data: %s\n\ndata: [DONE]\n\n", string(data))
			if flusher != nil {
				flusher.Flush()
			}
			return
		}

		resp := map[string]any{
			"id":      "chatcmpl_final_2",
			"object":  "chat.completion",
			"created": time.Now().Unix(),
			"choices": []map[string]any{
				{
					"index": 0,
					"message": map[string]any{
						"role":    "assistant",
						"content": "The sum of 20 and 30 is 50.",
					},
					"finish_reason": "stop",
				},
			},
			"usage": map[string]any{
				"prompt_tokens":     35,
				"completion_tokens": 12,
				"total_tokens":      47,
			},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer llmServer.Close()

	// 3. Setup Gateway
	cfg := config.Default()
	cfg.Auth.MasterAdminKey = "sk-gw-master-admin-tool-loop-key"
	cfg.MCP.Enabled = true
	cfg.Security.Network.OutboundSSRF.AllowPrivateNetworks = true
	cfg.Security.Network.OutboundSSRF.AllowInsecureHTTP = true
	repo := storage.NewMemoryRepository()
	gw, err := server.New(cfg, repo, nil, nil)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	gw.StartWorkers(ctx)
	defer gw.Shutdown(ctx)

	ts := httptest.NewServer(gw.Handler())
	defer ts.Close()

	adminHeaders := map[string]string{"Authorization": "Bearer " + cfg.Auth.MasterAdminKey}

	// Helper for JSON calls
	doJSON := func(method, path string, headers map[string]string, body any, out any) (*http.Response, []byte) {
		var rdr io.Reader
		if body != nil {
			b, _ := json.Marshal(body)
			rdr = bytes.NewReader(b)
		}
		req, _ := http.NewRequest(method, ts.URL+path, rdr)
		req.Header.Set("Content-Type", "application/json")
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("request %s %s: %v", method, path, err)
		}
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if out != nil && len(raw) > 0 {
			_ = json.Unmarshal(raw, out)
		}
		return resp, raw
	}

	// 4. Create Org, Model Group, Deployment, Key
	var org domain.Organization
	doJSON(http.MethodPost, "/admin/v1/organizations", adminHeaders, map[string]any{
		"name": "Tool Loop Org",
		"slug": "tool-loop-org",
	}, &org)

	doJSON(http.MethodPost, "/admin/v1/organizations/"+org.ID+"/subscriptions", adminHeaders, map[string]any{
		"provider": "openai", "is_enabled": true,
	}, nil)

	var cred domain.ProviderCredential
	doJSON(http.MethodPost, "/admin/v1/credentials", adminHeaders, map[string]any{
		"org_id":   org.ID,
		"provider": "openai",
		"name":     "openai-test-cred",
		"base_url": llmServer.URL,
		"api_key":  "sk-dummy-test-key",
	}, &cred)

	var mg domain.ModelGroup
	doJSON(http.MethodPost, "/admin/v1/model-groups", adminHeaders, map[string]any{
		"org_id":           org.ID,
		"alias":            "gpt-4.1",
		"routing_strategy": "weighted-shuffle",
	}, &mg)

	var dep domain.Deployment
	doJSON(http.MethodPost, "/admin/v1/deployments", adminHeaders, map[string]any{
		"model_group_id":  mg.ID,
		"deployment_name": "openai-gpt-4-primary",
		"credential_id":   cred.ID,
		"global_model_id": "openai/gpt-4.1",
		"weight":          100,
	}, &dep)

	// Register MCP Server
	var srvResp struct {
		Server domain.MCPServer `json:"server"`
	}
	doJSON(http.MethodPost, "/admin/v1/mcp/servers", adminHeaders, map[string]any{
		"org_id":         org.ID,
		"name":           "Calculator Service",
		"slug":           "calculator",
		"transport_type": "streamable_http",
		"endpoint_url":   mcpServer.URL,
		"auth_type":      "none",
	}, &srvResp)
	mcpSrv := srvResp.Server

	// Sync Tools so calculator_add is catalogued in gateway repo
	doJSON(http.MethodPost, "/admin/v1/mcp/servers/"+mcpSrv.ID+"/sync", adminHeaders, nil, nil)

	var vk domain.VirtualKey
	doJSON(http.MethodPost, "/admin/v1/keys", adminHeaders, map[string]any{
		"org_id":              org.ID,
		"name":                "tool-loop-vk",
		"allowed_endpoints":   []string{"*"},
		"allowed_mcp_servers": []string{"*"},
	}, &vk)

	vkHeaders := map[string]string{"Authorization": "Bearer " + vk.RawKey}

	// 5. Test Synchronous Chat Completion with Server-Side MCP Tool Execution
	modelTurnCount.Store(0)
	var syncChatResp map[string]any
	resp, raw := doJSON(http.MethodPost, "/v1/chat/completions", vkHeaders, map[string]any{
		"model": "gpt-4.1",
		"messages": []map[string]any{
			{"role": "user", "content": "What is 20 + 30?"},
		},
		"tools": []map[string]any{
			{
				"type": "function",
				"function": map[string]any{
					"name": "calculator_add",
				},
			},
		},
	}, &syncChatResp)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("sync chat completion failed (%d): %s", resp.StatusCode, string(raw))
	}
	choices, _ := syncChatResp["choices"].([]any)
	if len(choices) == 0 {
		t.Fatalf("expected non-empty choices: %v", syncChatResp)
	}
	firstChoice, _ := choices[0].(map[string]any)
	msg, _ := firstChoice["message"].(map[string]any)
	content, _ := msg["content"].(string)
	if !strings.Contains(content, "The sum of 20 and 30 is 50.") {
		t.Fatalf("unexpected content after tool loop execution: %q (raw: %s, model turns: %d)", content, string(raw), modelTurnCount.Load())
	}
	if modelTurnCount.Load() != 2 {
		t.Fatalf("expected 2 turns through LLM (tool request + final answer), got %d", modelTurnCount.Load())
	}

	// 6. Test Streaming Chat Completion with Lookahead Buffering
	modelTurnCount.Store(0)
	streamReqBody, _ := json.Marshal(map[string]any{
		"model":  "gpt-4.1",
		"stream": true,
		"messages": []map[string]any{
			{"role": "user", "content": "What is 20 + 30?"},
		},
		"tools": []map[string]any{
			{
				"type": "function",
				"function": map[string]any{
					"name": "calculator_add",
				},
			},
		},
	})
	httpStreamReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/v1/chat/completions", bytes.NewReader(streamReqBody))
	httpStreamReq.Header.Set("Content-Type", "application/json")
	for k, v := range vkHeaders {
		httpStreamReq.Header.Set(k, v)
	}
	sResp, err := http.DefaultClient.Do(httpStreamReq)
	if err != nil {
		t.Fatalf("streaming request failed: %v", err)
	}
	defer sResp.Body.Close()

	if sResp.StatusCode != http.StatusOK {
		sRaw, _ := io.ReadAll(sResp.Body)
		t.Fatalf("streaming response failed (%d): %s", sResp.StatusCode, string(sRaw))
	}

	scanner := bufio.NewScanner(sResp.Body)
	var streamContent strings.Builder
	sawDone := false

	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		dataStr := strings.TrimPrefix(line, "data: ")
		if dataStr == "[DONE]" {
			sawDone = true
			break
		}
		var chunk map[string]any
		if err := json.Unmarshal([]byte(dataStr), &chunk); err == nil {
			cList, _ := chunk["choices"].([]any)
			if len(cList) > 0 {
				c0, _ := cList[0].(map[string]any)
				delta, _ := c0["delta"].(map[string]any)
				if cText, ok := delta["content"].(string); ok {
					streamContent.WriteString(cText)
				}
			}
		}
	}

	if !sawDone {
		t.Fatalf("streaming did not receive [DONE]")
	}
	if !strings.Contains(streamContent.String(), "The sum of 20 and 30 is 50.") {
		t.Fatalf("unexpected streaming content: %s", streamContent.String())
	}
	if modelTurnCount.Load() != 2 {
		t.Fatalf("expected 2 turns during streaming tool loop, got %d", modelTurnCount.Load())
	}
}
