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
	"strings"
	"sync"
	"time"
)

type fixtureState struct {
	mu           sync.RWMutex
	siemSecret   string
	traceparents map[string][]string
	siemEvents   []map[string]any
}

func (s *fixtureState) recordTraceparent(provider, tp string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.traceparents == nil {
		s.traceparents = make(map[string][]string)
	}
	if strings.TrimSpace(tp) != "" {
		s.traceparents[provider] = append(s.traceparents[provider], strings.TrimSpace(tp))
	}
}

func (s *fixtureState) verifyHMAC(r *http.Request, body []byte) bool {
	if s.siemSecret == "" {
		return true
	}
	got := strings.TrimSpace(r.Header.Get("X-GoRoute-Signature-256"))
	mac := hmac.New(sha256.New, []byte(s.siemSecret))
	_, _ = mac.Write(body)
	want := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(got), []byte(want))
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
		siemSecret:   strings.TrimSpace(os.Getenv("OBS_SIEM_HMAC_SECRET")),
		traceparents: make(map[string][]string),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
	})

	// OpenAI-compatible mock handler (supports openai, groq, openrouter)
	handleOpenAICompat := func(provider, defaultModel, text string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			st.recordTraceparent(provider, r.Header.Get("traceparent"))
			if strings.HasSuffix(r.URL.Path, "/models") {
				writeJSON(w, http.StatusOK, map[string]any{
					"object": "list",
					"data":   []map[string]any{{"id": defaultModel, "object": "model", "owned_by": provider}},
				})
				return
			}
			body, _ := io.ReadAll(io.LimitReader(r.Body, 2<<20))
			var req struct {
				Model  string `json:"model"`
				Stream bool   `json:"stream"`
			}
			_ = json.Unmarshal(body, &req)
			model := req.Model
			if model == "" {
				model = defaultModel
			}
			if strings.HasSuffix(r.URL.Path, "/embeddings") {
				writeJSON(w, http.StatusOK, map[string]any{
					"object": "list",
					"model":  model,
					"data":   []map[string]any{{"object": "embedding", "index": 0, "embedding": []float64{0.1, 0.2, 0.3, 0.4}}},
					"usage":  map[string]any{"prompt_tokens": 14, "total_tokens": 14},
				})
				return
			}
			if req.Stream {
				w.Header().Set("Content-Type", "text/event-stream")
				w.Header().Set("Cache-Control", "no-cache")
				w.WriteHeader(http.StatusOK)
				flusher, _ := w.(http.Flusher)
				// Small delay before first token so gen_ai.server.time_to_first_token > 0ms is deterministic.
				time.Sleep(15 * time.Millisecond)
				chunk1 := fmt.Sprintf(`{"id":"chatcmpl_%s_stream","object":"chat.completion.chunk","created":%d,"model":%q,"choices":[{"index":0,"delta":{"role":"assistant","content":%q},"finish_reason":null}]}`, provider, time.Now().Unix(), model, text)
				_, _ = fmt.Fprintf(w, "data: %s\n\n", chunk1)
				if flusher != nil {
					flusher.Flush()
				}
				chunk2 := fmt.Sprintf(`{"id":"chatcmpl_%s_stream","object":"chat.completion.chunk","created":%d,"model":%q,"choices":[{"index":0,"delta":{},"finish_reason":"stop"}],"usage":{"prompt_tokens":22,"completion_tokens":11,"total_tokens":33}}`, provider, time.Now().Unix(), model)
				_, _ = fmt.Fprintf(w, "data: %s\n\n", chunk2)
				_, _ = fmt.Fprintf(w, "data: [DONE]\n\n")
				if flusher != nil {
					flusher.Flush()
				}
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{
				"id":      "chatcmpl_" + provider + "_obs",
				"object":  "chat.completion",
				"created": time.Now().Unix(),
				"model":   model,
				"choices": []map[string]any{{
					"index":         0,
					"message":       map[string]any{"role": "assistant", "content": text},
					"finish_reason": "stop",
				}},
				"usage": map[string]any{"prompt_tokens": 25, "completion_tokens": 15, "total_tokens": 40},
			})
		}
	}

	mux.HandleFunc("/openai/", handleOpenAICompat("openai", "gpt-4.1-mini", "openai-obs-ok"))
	mux.HandleFunc("/groq/", handleOpenAICompat("groq", "llama-3.3-70b-versatile", "groq-obs-ok"))
	mux.HandleFunc("/openrouter/", handleOpenAICompat("openrouter", "openai/gpt-4o-mini", "openrouter-obs-ok"))

	// Ollama mock handler (supports /api/tags, /v1/models, /v1/chat/completions, /v1/completions, /v1/embeddings)
	ollamaOpenAI := handleOpenAICompat("ollama", "qwen2.5:0.5b", "ollama-obs-ok")
	mux.HandleFunc("/ollama/", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/api/tags") {
			st.recordTraceparent("ollama", r.Header.Get("traceparent"))
			writeJSON(w, http.StatusOK, map[string]any{
				"models": []map[string]any{
					{"name": "qwen2.5:0.5b", "model": "qwen2.5:0.5b", "modified_at": time.Now().UTC().Format(time.RFC3339)},
					{"name": "all-minilm:latest", "model": "all-minilm:latest", "modified_at": time.Now().UTC().Format(time.RFC3339)},
				},
			})
			return
		}
		ollamaOpenAI(w, r)
	})

	// Anthropic Messages API mock handler
	mux.HandleFunc("/anthropic/", func(w http.ResponseWriter, r *http.Request) {
		st.recordTraceparent("anthropic", r.Header.Get("traceparent"))
		if strings.HasSuffix(r.URL.Path, "/models") {
			writeJSON(w, http.StatusOK, map[string]any{
				"data": []map[string]any{{"id": "claude-3-5-haiku-latest", "type": "model"}},
			})
			return
		}
		body, _ := io.ReadAll(io.LimitReader(r.Body, 2<<20))
		var req struct {
			Model string `json:"model"`
		}
		_ = json.Unmarshal(body, &req)
		model := req.Model
		if model == "" {
			model = "claude-3-5-haiku-latest"
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"id":          "msg_anthropic_obs",
			"type":        "message",
			"role":        "assistant",
			"model":       model,
			"content":     []map[string]any{{"type": "text", "text": "anthropic-obs-ok"}},
			"stop_reason": "end_turn",
			"usage":       map[string]any{"input_tokens": 18, "output_tokens": 9},
		})
	})

	// Google Gemini v1beta native API mock handler
	mux.HandleFunc("/gemini/", func(w http.ResponseWriter, r *http.Request) {
		st.recordTraceparent("gemini", r.Header.Get("traceparent"))
		_, _ = io.Copy(io.Discard, io.LimitReader(r.Body, 2<<20))
		switch {
		case strings.HasSuffix(r.URL.Path, "/models"):
			writeJSON(w, http.StatusOK, map[string]any{
				"models": []map[string]any{
					{"name": "models/gemini-2.5-flash", "displayName": "Gemini 2.5 Flash", "supportedGenerationMethods": []string{"generateContent"}},
					{"name": "models/gemini-embedding-001", "displayName": "Gemini Embedding 001", "supportedGenerationMethods": []string{"embedContent"}},
				},
			})
		case strings.HasSuffix(r.URL.Path, ":streamGenerateContent"):
			w.Header().Set("Content-Type", "text/event-stream")
			w.Header().Set("Cache-Control", "no-cache")
			w.WriteHeader(http.StatusOK)
			time.Sleep(15 * time.Millisecond)
			_, _ = fmt.Fprint(w, "data: {\"responseId\":\"resp_gemini_obs_stream\",\"modelVersion\":\"gemini-2.5-flash\",\"candidates\":[{\"index\":0,\"content\":{\"role\":\"model\",\"parts\":[{\"text\":\"gemini-obs-ok\"}]},\"finishReason\":\"STOP\"}],\"usageMetadata\":{\"promptTokenCount\":20,\"candidatesTokenCount\":8,\"thoughtsTokenCount\":4,\"totalTokenCount\":32}}\n\n")
		case strings.HasSuffix(r.URL.Path, ":embedContent"):
			writeJSON(w, http.StatusOK, map[string]any{
				"embedding": map[string]any{"values": []float64{0.1, 0.2, 0.3, 0.4}},
			})
		case strings.HasSuffix(r.URL.Path, ":batchEmbedContents"):
			writeJSON(w, http.StatusOK, map[string]any{
				"embeddings": []map[string]any{{"values": []float64{0.1, 0.2}}, {"values": []float64{0.3, 0.4}}},
			})
		default:
			writeJSON(w, http.StatusOK, map[string]any{
				"responseId":   "resp_gemini_obs",
				"modelVersion": "gemini-2.5-flash",
				"candidates": []map[string]any{{
					"index": 0,
					"content": map[string]any{
						"role":  "model",
						"parts": []map[string]any{{"text": "gemini-obs-ok"}},
					},
					"finishReason": "STOP",
				}},
				"usageMetadata": map[string]any{
					"promptTokenCount":     20,
					"candidatesTokenCount": 8,
					"thoughtsTokenCount":   4,
					"totalTokenCount":      32,
				},
			})
		}
	})

	// Streamable HTTP MCP Server (/mcp)
	mux.HandleFunc("/mcp", handleMCPFixture(st))

	// A2A Agent (/a2a)
	mux.HandleFunc("/a2a/.well-known/agent-card.json", func(w http.ResponseWriter, r *http.Request) {
		st.recordTraceparent("a2a", r.Header.Get("traceparent"))
		writeJSON(w, http.StatusOK, map[string]any{
			"name":               "Obs Fixture Agent",
			"description":        "Deterministic A2A observability fixture",
			"url":                "https://fixtures.prod.test:20443/a2a",
			"version":            "1.0.0",
			"defaultInputModes":  []string{"text/plain"},
			"defaultOutputModes": []string{"text/plain"},
		})
	})
	mux.HandleFunc("/a2a", func(w http.ResponseWriter, r *http.Request) {
		st.recordTraceparent("a2a", r.Header.Get("traceparent"))
		_, _ = io.Copy(io.Discard, io.LimitReader(r.Body, 1<<20))
		writeJSON(w, http.StatusOK, map[string]any{
			"task": map[string]any{
				"id":     "task_obs_fixture_1",
				"status": map[string]any{"state": "TASK_STATE_COMPLETED"},
				"artifacts": []map[string]any{{
					"name":  "result",
					"parts": []map[string]any{{"text": "obs-fixture-a2a-ok"}},
				}},
			},
		})
	})

	// SIEM Audit Webhook Collector (/siem/audit)
	mux.HandleFunc("/siem/audit", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 4<<20))
		if !st.verifyHMAC(r, body) {
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
		st.mu.Unlock()
		writeJSON(w, http.StatusAccepted, map[string]any{"accepted": len(payload.Events)})
	})

	// Inspection endpoints for E2E assertions
	mux.HandleFunc("/_inspect/traceparents", func(w http.ResponseWriter, _ *http.Request) {
		st.mu.RLock()
		defer st.mu.RUnlock()
		out := make(map[string][]string, len(st.traceparents))
		for k, v := range st.traceparents {
			cp := make([]string, len(v))
			copy(cp, v)
			out[k] = cp
		}
		writeJSON(w, http.StatusOK, out)
	})
	mux.HandleFunc("/_inspect/siem", func(w http.ResponseWriter, _ *http.Request) {
		st.mu.RLock()
		defer st.mu.RUnlock()
		writeJSON(w, http.StatusOK, map[string]any{
			"count":  len(st.siemEvents),
			"events": st.siemEvents,
		})
	})
	mux.HandleFunc("/_inspect/reset", func(w http.ResponseWriter, _ *http.Request) {
		st.mu.Lock()
		st.traceparents = make(map[string][]string)
		st.siemEvents = nil
		st.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{"reset": true})
	})

	log.Printf("obs-test-fixtures listening on %s", addr)
	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	if err := srv.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

func handleMCPFixture(st *fixtureState) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		st.recordTraceparent("mcp", r.Header.Get("traceparent"))
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
					"serverInfo":      map[string]any{"name": "obs-fixture-mcp", "version": "1.0.0"},
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
						{
							"name":        "lookup_status",
							"description": "Lookup deterministic observability fixture status",
							"inputSchema": map[string]any{"type": "object", "properties": map[string]any{"service": map[string]any{"type": "string"}}},
						},
					},
				},
			})
		case "tools/call":
			toolName, _ := rpc.Params["name"].(string)
			writeJSON(w, http.StatusOK, map[string]any{
				"jsonrpc": "2.0",
				"id":      rpc.ID,
				"result": map[string]any{
					"content": []map[string]any{{
						"type": "text",
						"text": "obs-mcp-ok tool=" + toolName,
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
	}
}
