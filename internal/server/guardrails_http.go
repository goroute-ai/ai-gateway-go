package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/guardrails"
	"github.com/goroute-ai/ai-gateway-go/internal/security/network"
)

// HTTPGuardrailScanner calls an external HTTP/webhook guardrail scanner endpoint
// using an SSRF-protected HTTP client.
type HTTPGuardrailScanner struct {
	name     string
	url      string
	timeout  time.Duration
	failOpen bool
	headers  map[string]string
	client   *http.Client
}

type httpScannerPayload struct {
	OrgID     string                   `json:"org_id"`
	Direction guardrails.ScanDirection `json:"direction"`
	Content   string                   `json:"content"`
}

type httpScannerResponse struct {
	Decision   string   `json:"decision"`
	Violations []string `json:"violations"`
}

// NewHTTPGuardrailScanners builds HTTPGuardrailScanner instances from GuardrailsConfig
// routed through network.NewHTTPClient(ssrfPolicy).
func NewHTTPGuardrailScanners(cfg config.GuardrailsConfig, ssrfPolicy *network.Policy) (time.Duration, bool, []guardrails.Scanner) {
	if len(cfg.Scanners) == 0 {
		return 0, false, nil
	}
	client := network.NewHTTPClient(ssrfPolicy)
	scanners := make([]guardrails.Scanner, 0, len(cfg.Scanners))
	maxTimeout := 2 * time.Second
	failClosed := false

	for _, sc := range cfg.Scanners {
		timeout := 2 * time.Second
		if sc.TimeoutMs > 0 {
			timeout = time.Duration(sc.TimeoutMs) * time.Millisecond
		}
		if timeout > maxTimeout {
			maxTimeout = timeout
		}
		if !sc.FailOpen {
			failClosed = true
		}
		resolvedHeaders := make(map[string]string, len(sc.Headers))
		for k, v := range sc.Headers {
			resolvedHeaders[k] = config.ResolveEnvValue(v)
		}
		scanners = append(scanners, &HTTPGuardrailScanner{
			name:     sc.Name,
			url:      strings.TrimSpace(sc.URL),
			timeout:  timeout,
			failOpen: sc.FailOpen,
			headers:  resolvedHeaders,
			client:   client,
		})
	}
	return maxTimeout, failClosed, scanners
}

// ConfigureGuardrailScannersFromConfig wires external HTTP guardrail scanners from config
// into the server's guardrail engine via ConfigureGuardrailScanners.
func (s *GatewayServer) ConfigureGuardrailScannersFromConfig(cfg config.GuardrailsConfig, ssrfPolicy *network.Policy) {
	if len(cfg.Scanners) == 0 {
		return
	}
	timeout, failClosed, scanners := NewHTTPGuardrailScanners(cfg, ssrfPolicy)
	s.ConfigureGuardrailScanners(timeout, failClosed, scanners...)
}

func (h *HTTPGuardrailScanner) Scan(ctx context.Context, req guardrails.ScanRequest) (guardrails.ScanResult, error) {
	if h.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, h.timeout)
		defer cancel()
	}

	body, err := json.Marshal(httpScannerPayload{
		OrgID:     req.OrgID,
		Direction: req.Direction,
		Content:   req.Content,
	})
	if err != nil {
		return h.handleFailure(fmt.Errorf("guardrail scanner %q marshal: %w", h.name, err))
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, h.url, bytes.NewReader(body))
	if err != nil {
		return h.handleFailure(fmt.Errorf("guardrail scanner %q request: %w", h.name, err))
	}
	httpReq.Header.Set("Content-Type", "application/json")
	for k, v := range h.headers {
		httpReq.Header.Set(k, v)
	}

	resp, err := h.client.Do(httpReq)
	if err != nil {
		return h.handleFailure(fmt.Errorf("guardrail scanner %q post: %w", h.name, err))
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return h.handleFailure(fmt.Errorf("guardrail scanner %q read: %w", h.name, err))
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return h.handleFailure(fmt.Errorf("guardrail scanner %q returned HTTP %d", h.name, resp.StatusCode))
	}

	var parsed httpScannerResponse
	if len(bytes.TrimSpace(respBytes)) > 0 {
		if err := json.Unmarshal(respBytes, &parsed); err != nil {
			return h.handleFailure(fmt.Errorf("guardrail scanner %q decode: %w", h.name, err))
		}
	}

	if strings.EqualFold(strings.TrimSpace(parsed.Decision), string(guardrails.ScannerDecisionBlock)) {
		return guardrails.ScanResult{
			Decision:   guardrails.ScannerDecisionBlock,
			Violations: parsed.Violations,
		}, nil
	}
	return guardrails.ScanResult{
		Decision:   guardrails.ScannerDecisionAllow,
		Violations: parsed.Violations,
	}, nil
}

func (h *HTTPGuardrailScanner) handleFailure(err error) (guardrails.ScanResult, error) {
	if h.failOpen {
		return guardrails.ScanResult{Decision: guardrails.ScannerDecisionAllow}, nil
	}
	return guardrails.ScanResult{}, err
}
