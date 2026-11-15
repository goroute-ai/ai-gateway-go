package server

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/guardrails"
	"github.com/goroute-ai/ai-gateway-go/internal/guardrails/drivers"
	"github.com/goroute-ai/ai-gateway-go/internal/security/network"
)

const defaultHTTPScannerTimeout = 2 * time.Second

// HTTPGuardrailScanner calls an external HTTP/webhook guardrail scanner endpoint
// using an SSRF-protected HTTP client, enforcing its own timeout and fail-open policy.
// It implements both guardrails.Scanner (legacy engine path) and guardrails.Driver (pipeline v2 path).
type HTTPGuardrailScanner struct {
	name     string
	url      string
	timeout  time.Duration
	failOpen bool
	headers  map[string]string
	client   *http.Client
	driver   *drivers.GenericHTTPDriver
	initErr  error
}

// NewHTTPGuardrailScanners builds HTTPGuardrailScanner instances from GuardrailsConfig
// routed through network.NewHTTPClient(ssrfPolicy). Each scanner enforces its own
// TimeoutMs deadline and FailOpen behavior independently.
func NewHTTPGuardrailScanners(cfg config.GuardrailsConfig, ssrfPolicy *network.Policy) (time.Duration, bool, []guardrails.Scanner) {
	if len(cfg.Scanners) == 0 {
		return 0, false, nil
	}
	client := network.NewHTTPClient(ssrfPolicy)
	scanners := make([]guardrails.Scanner, 0, len(cfg.Scanners))
	var maxTimeout time.Duration
	failClosed := false

	for _, sc := range cfg.Scanners {
		timeout := defaultHTTPScannerTimeout
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

		rawURL := strings.TrimSpace(sc.URL)
		name := strings.TrimSpace(sc.Name)
		if name == "" {
			name = drivers.DriverNameGenericHTTP
		}

		timeoutMs := sc.TimeoutMs
		if timeoutMs <= 0 {
			timeoutMs = int(timeout.Milliseconds())
		}

		drv, err := drivers.NewGenericHTTPDriver(guardrails.DriverConfig{
			Definition: &domain.GuardrailDefinition{
				Name:      name,
				Provider:  drivers.DriverNameGenericHTTP,
				TimeoutMs: timeoutMs,
				FailOpen:  sc.FailOpen,
			},
			EffectiveConfig: map[string]any{
				"url":        rawURL,
				"headers":    resolvedHeaders,
				"timeout_ms": timeoutMs,
			},
		}, client)

		scanners = append(scanners, &HTTPGuardrailScanner{
			name:     name,
			url:      rawURL,
			timeout:  timeout,
			failOpen: sc.FailOpen,
			headers:  resolvedHeaders,
			client:   client,
			driver:   drv,
			initErr:  err,
		})
	}
	return maxTimeout, failClosed, scanners
}

// ConfigureGuardrailScannersFromConfig registers the generic_http driver on the server's
// guardrail pipeline and wires configured external HTTP guardrail scanners into the engine.
func (s *GatewayServer) ConfigureGuardrailScannersFromConfig(cfg config.GuardrailsConfig, ssrfPolicy *network.Policy) {
	if s == nil {
		return
	}
	sharedClient := network.NewHTTPClient(ssrfPolicy)
	if pipeline := s.GuardrailPipeline(); pipeline != nil {
		pipeline.RegisterDriver(drivers.DriverNameGenericHTTP, func(_ context.Context, dcfg guardrails.DriverConfig) (guardrails.Driver, error) {
			return drivers.NewGenericHTTPDriver(dcfg, sharedClient)
		})
	}
	if len(cfg.Scanners) == 0 {
		return
	}
	timeout, failClosed, scanners := NewHTTPGuardrailScanners(cfg, ssrfPolicy)
	s.ConfigureGuardrailScanners(timeout, failClosed, scanners...)
}

// Name returns the configured scanner name.
func (h *HTTPGuardrailScanner) Name() string {
	if h == nil || h.name == "" {
		return drivers.DriverNameGenericHTTP
	}
	return h.name
}

// SupportedHooks returns nil so the scanner participates in any pipeline hook when used as a Driver.
func (h *HTTPGuardrailScanner) SupportedHooks() []domain.GuardrailHook {
	return nil
}

// Evaluate runs the rich generic_http driver evaluation, honoring this scanner's own TimeoutMs and FailOpen.
func (h *HTTPGuardrailScanner) Evaluate(ctx context.Context, input *domain.GuardrailEvalInput) (*domain.GuardrailEvalResult, error) {
	if h == nil {
		return nil, fmt.Errorf("http guardrail scanner is nil")
	}
	if h.initErr != nil {
		if h.failOpen {
			return &domain.GuardrailEvalResult{
				Decision:          domain.GuardrailDecisionAllow,
				AppliedGuardrails: []string{h.Name()},
				ErrorMessage:      h.initErr.Error(),
			}, nil
		}
		return nil, h.initErr
	}
	if h.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, h.timeout)
		defer cancel()
	}
	res, err := h.driver.Evaluate(ctx, input)
	if err != nil {
		if h.failOpen {
			return &domain.GuardrailEvalResult{
				Decision:          domain.GuardrailDecisionAllow,
				AppliedGuardrails: []string{h.Name()},
				ErrorMessage:      err.Error(),
			}, nil
		}
		return nil, err
	}
	return res, nil
}

// Scan implements guardrails.Scanner for legacy Engine checks while sending the rich generic_http
// envelope and enforcing this scanner's independent timeout and fail-open policy.
func (h *HTTPGuardrailScanner) Scan(ctx context.Context, req guardrails.ScanRequest) (guardrails.ScanResult, error) {
	if h.initErr != nil {
		return h.handleFailure(h.initErr)
	}
	if h.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, h.timeout)
		defer cancel()
	}

	input := &domain.GuardrailEvalInput{
		Direction: string(req.Direction),
		OrgID:     req.OrgID,
		Texts:     []string{req.Content},
	}
	res, err := h.driver.Evaluate(ctx, input)
	if err != nil {
		return h.handleFailure(fmt.Errorf("guardrail scanner %q: %w", h.name, err))
	}

	violations := collectViolationLabels(res)
	if res != nil && res.Decision == domain.GuardrailDecisionBlock {
		return guardrails.ScanResult{
			Decision:   guardrails.ScannerDecisionBlock,
			Violations: violations,
		}, nil
	}
	return guardrails.ScanResult{
		Decision:   guardrails.ScannerDecisionAllow,
		Violations: violations,
	}, nil
}

func (h *HTTPGuardrailScanner) handleFailure(err error) (guardrails.ScanResult, error) {
	if h.failOpen {
		return guardrails.ScanResult{Decision: guardrails.ScannerDecisionAllow}, nil
	}
	return guardrails.ScanResult{}, err
}

func collectViolationLabels(res *domain.GuardrailEvalResult) []string {
	if res == nil || len(res.Violations) == 0 {
		return nil
	}
	out := make([]string, 0, len(res.Violations))
	for _, v := range res.Violations {
		switch {
		case v.Rule != "":
			out = append(out, v.Rule)
		case v.Category != "":
			out = append(out, v.Category)
		case v.Message != "":
			out = append(out, v.Message)
		}
	}
	return out
}
