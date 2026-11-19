package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type webhookRecord struct {
	AuthHeader string          `json:"auth_header,omitempty"`
	Body       json.RawMessage `json:"body"`
	ReceivedAt string          `json:"received_at"`
}

var (
	totalRequests atomic.Int64
	secretPNGHits atomic.Int64
	lastTrace     atomic.Value
	jwksOutage    atomic.Bool

	mockRSAKey *rsa.PrivateKey
	mockRSAKID = "mock-rsa-1"

	hibpMu       sync.Mutex
	hibpPrefixes []string

	webhookMu        sync.Mutex
	softBudgetHooks  []webhookRecord
	keyRotationHooks []webhookRecord
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

	var keyErr error
	mockRSAKey, keyErr = rsa.GenerateKey(rand.Reader, 2048)
	if keyErr != nil {
		log.Fatalf("generate mock RSA keypair: %v", keyErr)
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
	mux.HandleFunc("/oidc/.well-known/openid-configuration", handleOIDCDiscovery)
	mux.HandleFunc("/oidc/jwks", handleOIDCJWKS)
	mux.HandleFunc("/oidc/admin/mint-jwt", handleOIDCMintJWT)
	mux.HandleFunc("/oidc/admin/jwks-outage", handleOIDCJWKSOutage)
	mux.HandleFunc("/hibp/range/", handleHIBPRange)
	mux.HandleFunc("/hibp/audit", handleHIBPAudit)
	mux.HandleFunc("/webhooks/soft-budget", handleWebhookSoftBudget)
	mux.HandleFunc("/webhooks/key-rotation", handleWebhookKeyRotation)
	mux.HandleFunc("/webhooks/audit", handleWebhookAudit)

	wrapped := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		if p != "/healthz" && p != "/debug/stats" && !strings.HasPrefix(p, "/oidc/admin/") && p != "/hibp/audit" && p != "/webhooks/audit" {
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

func handleOIDCDiscovery(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                "https://mock-upstream:8443/oidc",
		"authorization_endpoint":                "https://mock-upstream:8443/oidc/authorize",
		"token_endpoint":                        "https://mock-upstream:8443/oidc/token",
		"userinfo_endpoint":                     "https://mock-upstream:8443/oidc/userinfo",
		"jwks_uri":                              "https://mock-upstream:8443/oidc/jwks",
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
	})
}

func handleOIDCJWKS(w http.ResponseWriter, r *http.Request) {
	if jwksOutage.Load() {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "jwks_unavailable"})
		return
	}
	n := base64.RawURLEncoding.EncodeToString(mockRSAKey.PublicKey.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(mockRSAKey.PublicKey.E)).Bytes())
	writeJSON(w, http.StatusOK, map[string]any{
		"keys": []map[string]any{{
			"kty": "RSA",
			"kid": mockRSAKID,
			"use": "sig",
			"alg": "RS256",
			"n":   n,
			"e":   e,
		}},
	})
}

func handleOIDCMintJWT(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	var req struct {
		Sub     string   `json:"sub"`
		Email   string   `json:"email"`
		OrgID   string   `json:"org_id"`
		TeamIDs []string `json:"team_ids"`
		Role    string   `json:"role"`
		Aud     string   `json:"aud"`
		TTLSec  int64    `json:"ttl_sec"`
		KID     string   `json:"kid"`
		Iss     string   `json:"iss"`
	}
	if len(body) > 0 {
		_ = json.Unmarshal(body, &req)
	}
	if strings.TrimSpace(req.Iss) == "" {
		req.Iss = "https://mock-upstream:8443/oidc"
	}
	if strings.TrimSpace(req.Aud) == "" {
		req.Aud = "goroute-gateway"
	}
	if req.TTLSec <= 0 {
		req.TTLSec = 600
	}
	if strings.TrimSpace(req.KID) == "" {
		req.KID = mockRSAKID
	}
	now := time.Now().UTC().Unix()
	claims := map[string]any{
		"iss": req.Iss,
		"sub": req.Sub,
		"aud": req.Aud,
		"iat": now,
		"exp": now + req.TTLSec,
	}
	if req.Email != "" {
		claims["email"] = req.Email
	}
	if req.OrgID != "" {
		claims["org_id"] = req.OrgID
	}
	if len(req.TeamIDs) > 0 {
		claims["team_ids"] = req.TeamIDs
	}
	if req.Role != "" {
		claims["role"] = req.Role
	}
	hdrBytes, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT", "kid": req.KID})
	payBytes, _ := json.Marshal(claims)
	signingInput := base64.RawURLEncoding.EncodeToString(hdrBytes) + "." + base64.RawURLEncoding.EncodeToString(payBytes)
	digest := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, mockRSAKey, crypto.SHA256, digest[:])
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	tok := signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
	writeJSON(w, http.StatusOK, map[string]string{"token": tok})
}

func handleOIDCJWKSOutage(w http.ResponseWriter, r *http.Request) {
	fail := r.URL.Query().Get("fail")
	jwksOutage.Store(fail == "1" || strings.EqualFold(fail, "true"))
	writeJSON(w, http.StatusOK, map[string]any{"jwks_outage": jwksOutage.Load()})
}

func handleHIBPRange(w http.ResponseWriter, r *http.Request) {
	prefix := strings.ToUpper(strings.TrimPrefix(r.URL.Path, "/hibp/range/"))
	hibpMu.Lock()
	hibpPrefixes = append(hibpPrefixes, prefix)
	hibpMu.Unlock()

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	if strings.EqualFold(prefix, "CBFDA") {
		_, _ = io.WriteString(w, "C6008F9CAB4083784CBD1874F76618D2A97:99999\r\n")
		return
	}
	_, _ = io.WriteString(w, "00000000000000000000000000000000000:0\r\n")
}

func handleHIBPAudit(w http.ResponseWriter, r *http.Request) {
	hibpMu.Lock()
	cp := append([]string(nil), hibpPrefixes...)
	hibpMu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"prefixes": cp, "count": len(cp)})
}

func handleWebhookSoftBudget(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	raw := json.RawMessage(body)
	if !json.Valid(raw) {
		raw, _ = json.Marshal(string(body))
	}
	webhookMu.Lock()
	softBudgetHooks = append(softBudgetHooks, webhookRecord{
		AuthHeader: r.Header.Get("Authorization"),
		Body:       raw,
		ReceivedAt: time.Now().UTC().Format(time.RFC3339Nano),
	})
	webhookMu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func handleWebhookKeyRotation(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	raw := json.RawMessage(body)
	if !json.Valid(raw) {
		raw, _ = json.Marshal(string(body))
	}
	webhookMu.Lock()
	keyRotationHooks = append(keyRotationHooks, webhookRecord{
		AuthHeader: r.Header.Get("Authorization"),
		Body:       raw,
		ReceivedAt: time.Now().UTC().Format(time.RFC3339Nano),
	})
	webhookMu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func handleWebhookAudit(w http.ResponseWriter, r *http.Request) {
	webhookMu.Lock()
	softCopy := append([]webhookRecord(nil), softBudgetHooks...)
	rotCopy := append([]webhookRecord(nil), keyRotationHooks...)
	webhookMu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{
		"soft_budget":  softCopy,
		"key_rotation": rotCopy,
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
