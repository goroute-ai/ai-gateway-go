package server

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/security/network"
)

// AuditSIEMSinkConfig configures async batched audit log export to an external SIEM webhook.
type AuditSIEMSinkConfig struct {
	URL           string
	Secret        string
	AuthHeader    string
	BatchSize     int
	FlushInterval time.Duration
	Timeout       time.Duration
	MaxQueueSize  int
}

// AuditSIEMSink asynchronously delivers administrative audit records in signed JSON batches
// over GoRoute's SSRF-protected network.Policy without blocking API requests.
type AuditSIEMSink struct {
	url           string
	secret        string
	authHeader    string
	batchSize     int
	flushInterval time.Duration
	timeout       time.Duration
	httpClient    *http.Client

	ch        chan *domain.AuditLog
	dropped   atomic.Int64
	delivered atomic.Int64
	failed    atomic.Int64

	stopOnce sync.Once
	stopCh   chan struct{}
	doneCh   chan struct{}
}

// NewAuditSIEMSink creates and starts an async SIEM webhook sink.
func NewAuditSIEMSink(cfg AuditSIEMSinkConfig, netPolicy *network.Policy) *AuditSIEMSink {
	url := strings.TrimSpace(cfg.URL)
	if url == "" {
		return nil
	}
	batchSize := cfg.BatchSize
	if batchSize <= 0 {
		batchSize = 50
	}
	if batchSize > 500 {
		batchSize = 500
	}
	flushInterval := cfg.FlushInterval
	if flushInterval <= 0 {
		flushInterval = 5 * time.Second
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	queueSize := cfg.MaxQueueSize
	if queueSize <= 0 {
		queueSize = 4096
	}

	client := network.NewHTTPClient(netPolicy)
	client.Timeout = timeout

	sink := &AuditSIEMSink{
		url:           url,
		secret:        strings.TrimSpace(cfg.Secret),
		authHeader:    strings.TrimSpace(cfg.AuthHeader),
		batchSize:     batchSize,
		flushInterval: flushInterval,
		timeout:       timeout,
		httpClient:    client,
		ch:            make(chan *domain.AuditLog, queueSize),
		stopCh:        make(chan struct{}),
		doneCh:        make(chan struct{}),
	}
	go sink.loop()
	return sink
}

// Enqueue queues an audit log entry without blocking request execution.
func (s *AuditSIEMSink) Enqueue(log *domain.AuditLog) {
	if s == nil || log == nil {
		return
	}
	cp := *log
	select {
	case s.ch <- &cp:
	default:
		s.dropped.Add(1)
	}
}

// Stats returns delivery counters (delivered, failed, dropped).
func (s *AuditSIEMSink) Stats() (delivered, failed, dropped int64) {
	if s == nil {
		return 0, 0, 0
	}
	return s.delivered.Load(), s.failed.Load(), s.dropped.Load()
}

// Close flushes remaining buffered events and stops the background worker.
func (s *AuditSIEMSink) Close(ctx context.Context) {
	if s == nil {
		return
	}
	s.stopOnce.Do(func() {
		close(s.stopCh)
	})
	select {
	case <-s.doneCh:
	case <-ctx.Done():
	}
}

func (s *AuditSIEMSink) loop() {
	defer close(s.doneCh)
	ticker := time.NewTicker(s.flushInterval)
	defer ticker.Stop()

	batch := make([]*domain.AuditLog, 0, s.batchSize)
	flush := func() {
		if len(batch) == 0 {
			return
		}
		s.deliverBatch(batch)
		batch = batch[:0]
	}

	for {
		select {
		case ev := <-s.ch:
			batch = append(batch, ev)
			if len(batch) >= s.batchSize {
				flush()
			}
		case <-ticker.C:
			flush()
		case <-s.stopCh:
			for {
				select {
				case ev := <-s.ch:
					batch = append(batch, ev)
					if len(batch) >= s.batchSize {
						flush()
					}
				default:
					flush()
					return
				}
			}
		}
	}
}

func (s *AuditSIEMSink) deliverBatch(batch []*domain.AuditLog) {
	payload := map[string]any{
		"source":    "goroute-ai-gateway",
		"timestamp": time.Now().UTC().Format(time.RFC3339Nano),
		"events":    batch,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		s.failed.Add(int64(len(batch)))
		return
	}

	var lastErr error
	for attempt := range 3 {
		if attempt > 0 {
			time.Sleep(time.Duration(attempt) * 200 * time.Millisecond)
		}
		reqCtx, cancel := context.WithTimeout(context.Background(), s.timeout)
		req, reqErr := http.NewRequestWithContext(reqCtx, http.MethodPost, s.url, bytes.NewReader(body))
		if reqErr != nil {
			cancel()
			lastErr = reqErr
			break
		}
		req.Header.Set("Content-Type", "application/json")
		if s.authHeader != "" {
			req.Header.Set("Authorization", s.authHeader)
		}
		if s.secret != "" {
			mac := hmac.New(sha256.New, []byte(s.secret))
			_, _ = mac.Write(body)
			req.Header.Set("X-GoRoute-Signature-256", "sha256="+hex.EncodeToString(mac.Sum(nil)))
		}
		resp, doErr := s.httpClient.Do(req)
		cancel()
		if doErr != nil {
			lastErr = doErr
			continue
		}
		_ = resp.Body.Close()
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			s.delivered.Add(int64(len(batch)))
			return
		}
		lastErr = &domain.GatewayError{StatusCode: resp.StatusCode, Message: resp.Status}
	}
	s.failed.Add(int64(len(batch)))
	slog.Warn("audit SIEM webhook batch delivery failed", "url", s.url, "count", len(batch), "error", lastErr)
}
