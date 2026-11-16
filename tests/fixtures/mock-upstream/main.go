package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"
)

var (
	totalRequests atomic.Int64
	secretPNGHits atomic.Int64
	lastTrace     atomic.Value
)

const onePixelPNG = "\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15c4\x00\x00\x00\nIDATx\x9cc\x00\x01\x00\x00\x05\x00\x01\r\n-\xb4\x00\x00\x00\x00IEND\xaeB`\x82"

func loadHealthcheckCertPool(caFile, certFile string) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	for _, path := range []string{caFile, certFile} {
		if strings.TrimSpace(path) == "" {
			continue
		}
		pemBytes, err := os.ReadFile(path)
		if err == nil && pool.AppendCertsFromPEM(pemBytes) {
			return pool, nil
		}
	}
	return nil, errors.New("no readable TLS CA or leaf certificate for healthcheck")
}

func healthcheckURL(addr string) string {
	_, port, err := net.SplitHostPort(strings.TrimSpace(addr))
	if err != nil || port == "" {
		port = "8443"
	}
	return fmt.Sprintf("https://127.0.0.1:%s/healthz", port)
}

func runHealthcheck(addr, caFile, certFile string) error {
	pool, err := loadHealthcheckCertPool(caFile, certFile)
	if err != nil {
		return err
	}
	client := &http.Client{
		Timeout: 2 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
				RootCAs:    pool,
			},
		},
	}
	resp, err := client.Get(healthcheckURL(addr))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected healthcheck status: %d", resp.StatusCode)
	}
	return nil
}

func main() {
	addr := flag.String("addr", ":8443", "Listen address")
	certFile := flag.String("tls-cert", "/etc/goroute/tls/mock-upstream.crt", "TLS certificate path")
	keyFile := flag.String("tls-key", "/etc/goroute/tls/mock-upstream.key", "TLS private key path")
	caFile := flag.String("tls-ca", "/etc/goroute/tls/ca.crt", "TLS CA certificate path for healthcheck")
	healthcheck := flag.Bool("healthcheck", false, "Probe local /healthz over HTTPS and exit")
	flag.Parse()

	if *healthcheck {
		if err := runHealthcheck(*addr, *caFile, *certFile); err != nil {
			os.Exit(1)
		}
		os.Exit(0)
	}

	lastTrace.Store("")

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
	})
	mux.HandleFunc("/debug/stats", func(w http.ResponseWriter, r *http.Request) {
		tp, _ := lastTrace.Load().(string)
		writeJSON(w, http.StatusOK, map[string]any{
			"total_requests":   totalRequests.Load(),
			"secret_png_hits":  secretPNGHits.Load(),
			"last_traceparent": tp,
		})
	})
	mux.HandleFunc("/secret.png", func(w http.ResponseWriter, r *http.Request) {
		secretPNGHits.Add(1)
		log.Printf("SECRET_PNG_TRAP_HIT remote=%s", r.RemoteAddr)
		w.Header().Set("Content-Type", "image/png")
		_, _ = io.WriteString(w, onePixelPNG)
	})
	mux.HandleFunc("/v1/models", handleModels)
	mux.HandleFunc("/api/tags", handleOllamaTags)
	mux.HandleFunc("/api/chat", handleOllamaChat)
	mux.HandleFunc("/v1/chat/completions", handleChatCompletions)
	mux.HandleFunc("/v1/embeddings", handleEmbeddings)
	mux.HandleFunc("/v1/images/generations", handleImages)
	mux.HandleFunc("/v1/audio/speech", handleAudioSpeech)
	mux.HandleFunc("/v1/audio/transcriptions", handleAudioTranscriptions)
	mux.HandleFunc("/v1/messages", handleAnthropicMessages)
	mux.HandleFunc("/v1/messages/count_tokens", handleAnthropicCountTokens)
	mux.HandleFunc("/mcp", handleMCP)
	mux.HandleFunc("/.well-known/agent-card.json", handleAgentCard)
	mux.HandleFunc("/a2a", handleA2A)

	wrapped := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz" && r.URL.Path != "/debug/stats" {
			totalRequests.Add(1)
			if tp := r.Header.Get("Traceparent"); tp != "" {
				lastTrace.Store(tp)
			}
		}
		mux.ServeHTTP(w, r)
	})

	srv := &http.Server{
		Addr:              *addr,
		Handler:           wrapped,
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Printf("mock-upstream listening on %s (TLS)", *addr)
	log.Fatal(srv.ListenAndServeTLS(*certFile, *keyFile))
}

func handleModels(w http.ResponseWriter, r *http.Request) {
	models := []string{"gpt-4o-mini", "gpt-4o", "claude-sonnet-4-20250514", "text-embedding-3-small", "dall-e-3", "tts-1"}
	data := make([]map[string]any, 0, len(models))
	for _, m := range models {
		data = append(data, map[string]any{"id": m, "object": "model", "owned_by": "mock-upstream"})
	}
	writeJSON(w, http.StatusOK, map[string]any{"object": "list", "data": data})
}

func handleOllamaTags(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"models": []map[string]any{{"name": "llama3.2:1b", "model": "llama3.2:1b"}},
	})
}

func handleOllamaChat(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"model":      "llama3.2:1b",
		"created_at": time.Now().UTC().Format(time.RFC3339),
		"message":    map[string]any{"role": "assistant", "content": "Hello from mock-ollama!"},
		"done":       true,
	})
}

func handleChatCompletions(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	var req struct {
		Model    string `json:"model"`
		Stream   bool   `json:"stream"`
		Messages []struct {
			Role    string `json:"role"`
			Content any    `json:"content"`
		} `json:"messages"`
	}
	_ = json.Unmarshal(body, &req)
	if req.Model == "" {
		req.Model = "gpt-4o-mini"
	}

	replyText := "Hello from mock-upstream!"
	if strings.Contains(string(body), "TRIGGER_PII_OUTPUT") {
		replyText = "Contact alice@example.com for details."
	}

	if req.Stream {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		flusher, _ := w.(http.Flusher)
		chunks := []string{"Hello", " from", " mock-upstream!"}
		for i, c := range chunks {
			delta := map[string]any{"content": c}
			if i == 0 {
				delta["role"] = "assistant"
			}
			payload := map[string]any{
				"id":      "chatcmpl_mock_stream",
				"object":  "chat.completion.chunk",
				"created": 1700000000,
				"model":   req.Model,
				"choices": []map[string]any{{"index": 0, "delta": delta, "finish_reason": nil}},
			}
			b, _ := json.Marshal(payload)
			_, _ = fmt.Fprintf(w, "data: %s\n\n", b)
			if flusher != nil {
				flusher.Flush()
			}
		}
		finalChunk := map[string]any{
			"id":      "chatcmpl_mock_stream",
			"object":  "chat.completion.chunk",
			"created": 1700000000,
			"model":   req.Model,
			"choices": []map[string]any{{"index": 0, "delta": map[string]any{}, "finish_reason": "stop"}},
			"usage":   map[string]any{"prompt_tokens": 12, "completion_tokens": 8, "total_tokens": 20},
		}
		b, _ := json.Marshal(finalChunk)
		_, _ = fmt.Fprintf(w, "data: %s\n\ndata: [DONE]\n\n", b)
		if flusher != nil {
			flusher.Flush()
		}
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"id":      "chatcmpl_mock_1",
		"object":  "chat.completion",
		"created": 1700000000,
		"model":   req.Model,
		"choices": []map[string]any{{
			"index":         0,
			"message":       map[string]any{"role": "assistant", "content": replyText},
			"finish_reason": "stop",
		}},
		"usage": map[string]any{"prompt_tokens": 12, "completion_tokens": 8, "total_tokens": 20},
	})
}

func handleAnthropicMessages(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	var req struct {
		Model  string `json:"model"`
		Stream bool   `json:"stream"`
	}
	_ = json.Unmarshal(body, &req)
	if req.Model == "" {
		req.Model = "claude-sonnet-4-20250514"
	}
	if req.Stream {
		w.Header().Set("Content-Type", "text/event-stream")
		flusher, _ := w.(http.Flusher)
		events := []string{
			`event: message_start` + "\n" + `data: {"type":"message_start","message":{"id":"msg_mock_1","type":"message","role":"assistant","model":"` + req.Model + `","usage":{"input_tokens":10,"output_tokens":0}}}` + "\n\n",
			`event: content_block_start` + "\n" + `data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}` + "\n\n",
			`event: content_block_delta` + "\n" + `data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Mock Anthropic stream reply"}}` + "\n\n",
			`event: content_block_stop` + "\n" + `data: {"type":"content_block_stop","index":0}` + "\n\n",
			`event: message_delta` + "\n" + `data: {"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":6}}` + "\n\n",
			`event: message_stop` + "\n" + `data: {"type":"message_stop"}` + "\n\n",
		}
		for _, ev := range events {
			_, _ = io.WriteString(w, ev)
			if flusher != nil {
				flusher.Flush()
			}
		}
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"id":          "msg_mock_1",
		"type":        "message",
		"role":        "assistant",
		"model":       req.Model,
		"content":     []map[string]any{{"type": "text", "text": "Mock Anthropic reply"}},
		"stop_reason": "end_turn",
		"usage":       map[string]any{"input_tokens": 11, "output_tokens": 7},
	})
}

func handleAnthropicCountTokens(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"input_tokens": 10})
}

func handleEmbeddings(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	var req struct {
		Model string `json:"model"`
	}
	_ = json.Unmarshal(body, &req)
	if req.Model == "" {
		req.Model = "text-embedding-3-small"
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"object": "list",
		"model":  req.Model,
		"data":   []map[string]any{{"object": "embedding", "index": 0, "embedding": []float64{0.1, 0.2, 0.3, 0.4}}},
		"usage":  map[string]any{"prompt_tokens": 5, "total_tokens": 5},
	})
}

func handleImages(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"created": 1700000000,
		"data": []map[string]any{{
			"b64_json": "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==",
		}},
	})
}

func handleAudioSpeech(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if r.URL.Query().Get("badtype") == "html" || strings.Contains(string(body), "BADTYPE_HTML") {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, "<html>mock-spoofed-content-type</html>")
		return
	}
	w.Header().Set("Content-Type", "audio/mpeg")
	_, _ = io.WriteString(w, "ID3\x03\x00\x00\x00\x00\x00\x00mock-audio")
}

func handleAudioTranscriptions(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"text": "Mock transcription output"})
}

func handleMCP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	var req struct {
		JSONRPC string         `json:"jsonrpc"`
		ID      any            `json:"id"`
		Method  string         `json:"method"`
		Params  map[string]any `json:"params"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"jsonrpc": "2.0", "id": nil, "error": map[string]any{"code": -32700, "message": "parse error"}})
		return
	}
	switch req.Method {
	case "initialize":
		writeJSON(w, http.StatusOK, map[string]any{
			"jsonrpc": "2.0",
			"id":      req.ID,
			"result": map[string]any{
				"protocolVersion": "2026-07-28",
				"capabilities":    map[string]any{"tools": map[string]any{}},
				"serverInfo":      map[string]any{"name": "mock-mcp-server", "version": "1.0.0"},
			},
		})
	case "notifications/initialized", "ping":
		writeJSON(w, http.StatusOK, map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": map[string]any{}})
	case "tools/list":
		writeJSON(w, http.StatusOK, map[string]any{
			"jsonrpc": "2.0",
			"id":      req.ID,
			"result": map[string]any{
				"tools": []map[string]any{{
					"name":        "echo_tool",
					"description": "Echoes mock tool input",
					"inputSchema": map[string]any{
						"type":       "object",
						"properties": map[string]any{"msg": map[string]any{"type": "string"}},
					},
				}},
			},
		})
	case "tools/call":
		writeJSON(w, http.StatusOK, map[string]any{
			"jsonrpc": "2.0",
			"id":      req.ID,
			"result": map[string]any{
				"content": []map[string]any{{"type": "text", "text": "mock tool execution ok"}},
			},
		})
	default:
		writeJSON(w, http.StatusOK, map[string]any{
			"jsonrpc": "2.0",
			"id":      req.ID,
			"error":   map[string]any{"code": -32601, "message": "method not found"},
		})
	}
}

func handleAgentCard(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"name":               "mock-a2a-agent",
		"description":        "Mock A2A verification agent",
		"url":                "https://mock-upstream:8443/a2a",
		"version":            "1.0.0",
		"protocolVersions":   []string{"1.0"},
		"defaultInputModes":  []string{"text/plain"},
		"defaultOutputModes": []string{"text/plain"},
		"capabilities":       map[string]any{"streaming": false},
		"skills":             []map[string]any{{"id": "echo", "name": "Echo"}},
	})
}

func handleA2A(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"message": map[string]any{
			"messageId": "msg_mock_a2a_1",
			"role":      "ROLE_AGENT",
			"parts":     []map[string]any{{"text": "Acknowledged by mock A2A agent"}},
		},
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
