package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync"
	"time"
)

type authzPolicy struct {
	StatusCode int      `json:"status_code,omitempty"`
	DenyAll    bool     `json:"deny_all,omitempty"`
	DenyModels []string `json:"deny_models,omitempty"`
	DenyPaths  []string `json:"deny_paths,omitempty"`
	DenyTools  []string `json:"deny_tools,omitempty"`
	DenyAgents []string `json:"deny_agents,omitempty"`
	Reason     string   `json:"reason,omitempty"`
}

type fixtureState struct {
	mu          sync.RWMutex
	authzPolicy authzPolicy
	authzCalls  []map[string]any
	siemEvents  []map[string]any
	authzSecret string
	siemSecret  string
}

func (s *fixtureState) verifyHMAC(r *http.Request, body []byte, secret string) bool {
	if secret == "" {
		return true
	}
	got := strings.TrimSpace(r.Header.Get("X-GoRoute-Signature-256"))
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write(body)
	want := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(got), []byte(want))
}

func (s *fixtureState) evaluateAuthz(req map[string]any) (int, bool, string) {
	s.mu.RLock()
	pol := s.authzPolicy
	s.mu.RUnlock()

	if pol.StatusCode >= 400 {
		return pol.StatusCode, false, pol.Reason
	}
	if pol.DenyAll {
		reason := pol.Reason
		if reason == "" {
			reason = "denied by fixture policy"
		}
		return http.StatusOK, false, reason
	}
	model, _ := req["model"].(string)
	path, _ := req["http_path"].(string)
	tool, _ := req["mcp_tool"].(string)
	agent, _ := req["a2a_agent"].(string)
	if model != "" && slices.Contains(pol.DenyModels, model) {
		return http.StatusOK, false, fmt.Sprintf("model %q blocked by external policy", model)
	}
	for _, dp := range pol.DenyPaths {
		if dp != "" && strings.HasPrefix(path, dp) {
			return http.StatusOK, false, fmt.Sprintf("path %q blocked by external policy", path)
		}
	}
	if tool != "" && slices.Contains(pol.DenyTools, tool) {
		return http.StatusOK, false, fmt.Sprintf("tool %q blocked by external policy", tool)
	}
	if agent != "" && slices.Contains(pol.DenyAgents, agent) {
		return http.StatusOK, false, fmt.Sprintf("agent %q blocked by external policy", agent)
	}
	return http.StatusOK, true, ""
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func main() {
	addr := strings.TrimSpace(os.Getenv("FIXTURES_ADDR"))
	if addr == "" {
		addr = ":8080"
	}
	st := &fixtureState{
		authzSecret: strings.TrimSpace(os.Getenv("PROD_AUTHZ_HMAC_SECRET")),
		siemSecret:  strings.TrimSpace(os.Getenv("PROD_SIEM_HMAC_SECRET")),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
	})

	// Mock regional LLM upstreams (/llm/eu/* and /llm/us/*)
	handleRegionLLM := func(region, content string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Mock-Region", region)
			switch {
			case strings.HasSuffix(r.URL.Path, "/models"):
				writeJSON(w, http.StatusOK, map[string]any{
					"object": "list",
					"data":   []map[string]any{{"id": "gpt-4o-mini", "object": "model", "owned_by": region}},
				})
			case strings.HasSuffix(r.URL.Path, "/embeddings"):
				writeJSON(w, http.StatusOK, map[string]any{
					"object": "list",
					"model":  "text-embedding-3-small",
					"data":   []map[string]any{{"object": "embedding", "index": 0, "embedding": []float64{0.1, 0.2, 0.3}}},
					"usage":  map[string]any{"prompt_tokens": 25, "total_tokens": 25},
				})
			case strings.HasSuffix(r.URL.Path, "/responses"):
				writeJSON(w, http.StatusOK, map[string]any{
					"id":     "resp_" + region + "_1",
					"object": "response",
					"status": "completed",
					"model":  "gpt-4o-mini",
					"output": []map[string]any{{
						"type": "message",
						"role": "assistant",
						"content": []map[string]any{{
							"type": "output_text",
							"text": content,
						}},
					}},
					"usage": map[string]any{"input_tokens": 100, "output_tokens": 50, "total_tokens": 150},
				})
			default:
				writeJSON(w, http.StatusOK, map[string]any{
					"id":      "chatcmpl_" + region + "_1",
					"object":  "chat.completion",
					"created": time.Now().Unix(),
					"model":   "gpt-4o-mini",
					"choices": []map[string]any{{
						"index":         0,
						"message":       map[string]any{"role": "assistant", "content": content},
						"finish_reason": "stop",
					}},
					"usage": map[string]any{"prompt_tokens": 100, "completion_tokens": 50, "total_tokens": 150},
				})
			}
		}
	}
	mux.HandleFunc("/llm/eu/", handleRegionLLM("eu-gdpr", "eu-deployment-ok"))
	mux.HandleFunc("/llm/us/", handleRegionLLM("us-east", "us-deployment-ok"))

	// Real Streamable HTTP MCP Server (/mcp)
	mux.HandleFunc("/mcp", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		var rpc struct {
			JSONRPC string         `json:"jsonrpc"`
			ID      any            `json:"id"`
			Method  string         `json:"method"`
			Params  map[string]any `json:"params"`
		}
		_ = json.Unmarshal(body, &rpc)
		switch rpc.Method {
		case "initialize":
			writeJSON(w, http.StatusOK, map[string]any{
				"jsonrpc": "2.0",
				"id":      rpc.ID,
				"result": map[string]any{
					"protocolVersion": "2026-07-28",
					"capabilities":    map[string]any{"tools": map[string]any{}},
					"serverInfo":      map[string]any{"name": "prod-fixture-mcp", "version": "1.0.0"},
				},
			})
		case "notifications/initialized":
			w.WriteHeader(http.StatusAccepted)
		case "tools/list":
			writeJSON(w, http.StatusOK, map[string]any{
				"jsonrpc": "2.0",
				"id":      rpc.ID,
				"result": map[string]any{
					"tools": []map[string]any{
						{"name": "get_issue", "description": "Read GitHub issue metadata", "inputSchema": map[string]any{"type": "object", "properties": map[string]any{"id": map[string]any{"type": "string"}}}},
						{"name": "list_files", "description": "List repository files", "inputSchema": map[string]any{"type": "object", "properties": map[string]any{"path": map[string]any{"type": "string"}}}},
						{"name": "delete_repo", "description": "Permanently delete repository", "inputSchema": map[string]any{"type": "object", "properties": map[string]any{"repo": map[string]any{"type": "string"}}}},
						{"name": "admin_wipe", "description": "Wipe tenant workspace", "inputSchema": map[string]any{"type": "object"}},
					},
				},
			})
		case "tools/call":
			toolName, _ := rpc.Params["name"].(string)
			args, _ := json.Marshal(rpc.Params["arguments"])
			writeJSON(w, http.StatusOK, map[string]any{
				"jsonrpc": "2.0",
				"id":      rpc.ID,
				"result": map[string]any{
					"content": []map[string]any{{
						"type": "text",
						"text": fmt.Sprintf("fixture-mcp-ok tool=%s args=%s", toolName, string(args)),
					}},
				},
			})
		default:
			writeJSON(w, http.StatusOK, map[string]any{
				"jsonrpc": "2.0",
				"id":      rpc.ID,
				"error":   map[string]any{"code": -32601, "message": "method not found: " + rpc.Method},
			})
		}
	})

	// Real A2A Agent (/a2a)
	mux.HandleFunc("/a2a/.well-known/agent-card.json", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"name":               "Prod Fixture Researcher",
			"description":        "Deterministic A2A research fixture",
			"url":                "https://fixtures.prod.test:18443/a2a",
			"version":            "1.0.0",
			"defaultInputModes":  []string{"text/plain"},
			"defaultOutputModes": []string{"text/plain"},
		})
	})
	mux.HandleFunc("/a2a", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, io.LimitReader(r.Body, 1<<20))
		writeJSON(w, http.StatusOK, map[string]any{
			"task": map[string]any{
				"id":     "task_prod_fixture_1",
				"status": map[string]any{"state": "TASK_STATE_COMPLETED"},
				"artifacts": []map[string]any{{
					"name":  "result",
					"parts": []map[string]any{{"text": "prod-fixture-a2a-ok"}},
				}},
			},
		})
	})

	// External Policy Authorizer (Webhook + OPA modes)
	mux.HandleFunc("/authz/webhook", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if !st.verifyHMAC(r, body, st.authzSecret) {
			http.Error(w, "invalid signature", http.StatusUnauthorized)
			return
		}
		var req map[string]any
		_ = json.Unmarshal(body, &req)
		st.mu.Lock()
		st.authzCalls = append(st.authzCalls, map[string]any{
			"action":        req["action"],
			"resource_type": req["resource_type"],
			"resource_id":   req["resource_id"],
			"http_path":     req["http_path"],
			"hmac_verified": true,
		})
		if len(st.authzCalls) > 500 {
			st.authzCalls = st.authzCalls[len(st.authzCalls)-500:]
		}
		st.mu.Unlock()

		status, allow, reason := st.evaluateAuthz(req)
		if status >= 400 {
			http.Error(w, "simulated authorizer outage", status)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"allow":  allow,
			"reason": reason,
		})
	})
	mux.HandleFunc("/authz/opa/v1/data/goroute/allow", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if !st.verifyHMAC(r, body, st.authzSecret) {
			http.Error(w, "invalid signature", http.StatusUnauthorized)
			return
		}
		var env struct {
			Input map[string]any `json:"input"`
		}
		_ = json.Unmarshal(body, &env)
		status, allow, reason := st.evaluateAuthz(env.Input)
		if status >= 400 {
			http.Error(w, "simulated opa outage", status)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"result": map[string]any{"allow": allow, "reason": reason},
		})
	})
	mux.HandleFunc("/_control/authz", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			st.mu.RLock()
			defer st.mu.RUnlock()
			writeJSON(w, http.StatusOK, map[string]any{
				"policy": st.authzPolicy,
				"calls":  st.authzCalls,
			})
		case http.MethodPut:
			var pol authzPolicy
			if err := json.NewDecoder(r.Body).Decode(&pol); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			st.mu.Lock()
			st.authzPolicy = pol
			st.mu.Unlock()
			writeJSON(w, http.StatusOK, pol)
		case http.MethodDelete:
			st.mu.Lock()
			st.authzPolicy = authzPolicy{}
			st.authzCalls = nil
			st.mu.Unlock()
			writeJSON(w, http.StatusOK, map[string]any{"reset": true})
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})

	// SIEM Webhook Collector (/siem/audit)
	mux.HandleFunc("/siem/audit", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 4<<20))
		if !st.verifyHMAC(r, body, st.siemSecret) {
			http.Error(w, "invalid siem signature", http.StatusUnauthorized)
			return
		}
		var payload struct {
			Events []map[string]any `json:"events"`
		}
		if err := json.Unmarshal(body, &payload); err != nil {
			http.Error(w, "invalid json", http.StatusBadRequest)
			return
		}
		st.mu.Lock()
		for _, ev := range payload.Events {
			ev["hmac_verified"] = true
			st.siemEvents = append(st.siemEvents, ev)
		}
		if len(st.siemEvents) > 2000 {
			st.siemEvents = st.siemEvents[len(st.siemEvents)-2000:]
		}
		st.mu.Unlock()
		writeJSON(w, http.StatusAccepted, map[string]any{"accepted": len(payload.Events)})
	})
	mux.HandleFunc("/_control/siem/events", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			st.mu.Lock()
			st.siemEvents = nil
			st.mu.Unlock()
			writeJSON(w, http.StatusOK, map[string]any{"cleared": true})
			return
		}
		st.mu.RLock()
		defer st.mu.RUnlock()
		writeJSON(w, http.StatusOK, map[string]any{
			"count":  len(st.siemEvents),
			"events": st.siemEvents,
		})
	})

	log.Printf("prod-test-fixtures listening on %s", addr)
	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	if err := srv.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}
