package network

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/config"
)

type testRoundTripper func(*http.Request) (*http.Response, error)

func (fn testRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) { return fn(req) }

type progressBody struct {
	ctx       context.Context
	remaining int
	interval  time.Duration
}

func (b *progressBody) Read(p []byte) (int, error) {
	if b.remaining == 0 {
		return 0, io.EOF
	}
	timer := time.NewTimer(b.interval)
	defer timer.Stop()
	select {
	case <-b.ctx.Done():
		return 0, b.ctx.Err()
	case <-timer.C:
		b.remaining--
		return copy(p, "x"), nil
	}
}

func (b *progressBody) Close() error { return nil }

type contextBody struct{ ctx context.Context }

func (b contextBody) Read([]byte) (int, error) {
	<-b.ctx.Done()
	return 0, b.ctx.Err()
}
func (contextBody) Close() error { return nil }

func TestNewHTTPClientUsesIdleAndHeaderTimeoutsInsteadOfTotalTimeout(t *testing.T) {
	client := NewHTTPClient(nil)
	if client.Timeout != 0 {
		t.Fatalf("client total timeout = %s, want no total timeout", client.Timeout)
	}
	rt, ok := client.Transport.(idleTimeoutRoundTripper)
	if !ok {
		t.Fatalf("transport type = %T, want idleTimeoutRoundTripper", client.Transport)
	}
	transport, ok := rt.base.(*http.Transport)
	if !ok {
		t.Fatalf("base transport type = %T, want *http.Transport", rt.base)
	}
	if transport.ResponseHeaderTimeout != 2*time.Minute {
		t.Fatalf("response header timeout = %s, want 2m", transport.ResponseHeaderTimeout)
	}
	if transport.MaxIdleConnsPerHost != 16 || transport.MaxIdleConns != 256 {
		t.Fatalf("unexpected bounded idle pool: global=%d per-host=%d", transport.MaxIdleConns, transport.MaxIdleConnsPerHost)
	}
}

func TestNewHTTPClientUsesConfiguredPoolSizes(t *testing.T) {
	client := NewHTTPClientWithOptions(nil, HTTPClientOptions{
		RequestTimeout:        time.Minute,
		ResponseHeaderTimeout: 45 * time.Second,
		StreamIdleTimeout:     30 * time.Second,
		MaxIdleConns:          73,
		MaxIdleConnsPerHost:   9,
	}, nil)
	rt := client.Transport.(idleTimeoutRoundTripper)
	transport := rt.base.(*http.Transport)
	if transport.MaxIdleConns != 73 || transport.MaxIdleConnsPerHost != 9 {
		t.Fatalf("configured pool sizes = (%d,%d), want (73,9)", transport.MaxIdleConns, transport.MaxIdleConnsPerHost)
	}
	if transport.ResponseHeaderTimeout != 45*time.Second || rt.requestTimeout != time.Minute || rt.idleTimeout != 30*time.Second {
		t.Fatalf("configured timeouts = (%s,%s,%s)", rt.requestTimeout, transport.ResponseHeaderTimeout, rt.idleTimeout)
	}
}

func TestIdleTimeoutRoundTripperAllowsLongProgressingBody(t *testing.T) {
	base := testRoundTripper(func(req *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: &progressBody{ctx: req.Context(), remaining: 4, interval: 20 * time.Millisecond}}, nil
	})
	rt := idleTimeoutRoundTripper{base: base, idleTimeout: 50 * time.Millisecond}
	req, _ := http.NewRequest(http.MethodGet, "https://example.test", nil)
	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read progressing body: %v", err)
	}
	if string(got) != strings.Repeat("x", 4) {
		t.Fatalf("body = %q", got)
	}
}

func TestIdleTimeoutRoundTripperCancelsStalledBody(t *testing.T) {
	base := testRoundTripper(func(req *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: contextBody{ctx: req.Context()}}, nil
	})
	rt := idleTimeoutRoundTripper{base: base, idleTimeout: 25 * time.Millisecond}
	req, _ := http.NewRequest(http.MethodGet, "https://example.test", nil)
	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	start := time.Now()
	_, err = io.ReadAll(resp.Body)
	if err == nil {
		t.Fatal("expected idle timeout to interrupt the stalled body")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("read error = %v, want context cancellation", err)
	}
	if time.Since(start) > time.Second {
		t.Fatal("idle timeout did not interrupt the stalled body promptly")
	}
}

func TestIdleTimeoutRoundTripperAppliesTotalDeadlineOnlyToNonStreamingRequests(t *testing.T) {
	base := testRoundTripper(func(req *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: &progressBody{ctx: req.Context(), remaining: 4, interval: 20 * time.Millisecond}}, nil
	})
	rt := idleTimeoutRoundTripper{base: base, requestTimeout: 25 * time.Millisecond, idleTimeout: 100 * time.Millisecond}

	ordinary, _ := http.NewRequest(http.MethodGet, "https://example.test", nil)
	resp, err := rt.RoundTrip(ordinary)
	if err != nil {
		t.Fatal(err)
	}
	_, err = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("ordinary request error = %v, want deadline exceeded", err)
	}

	streaming, _ := http.NewRequest(http.MethodGet, "https://example.test", nil)
	streaming = streaming.WithContext(WithStreamingRequest(streaming.Context()))
	resp, err = rt.RoundTrip(streaming)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("streaming request exceeded total deadline: %v", err)
	}
	if string(data) != strings.Repeat("x", 4) {
		t.Fatalf("stream body = %q", data)
	}
}

func TestLoopbackHTTPContextResetsAcrossSchemesAndBlocksNonLoopbackDial(t *testing.T) {
	policy, err := NewPolicy(config.OutboundSSRFConfig{
		AllowPrivateNetworks: false,
		AllowInsecureHTTP:    false,
		AllowLoopbackHTTP:    true,
		AllowedPrivateCIDRs:  []string{"127.0.0.1/32", "10.0.0.0/8"},
	})
	if err != nil {
		t.Fatalf("NewPolicy: %v", err)
	}

	var seenFlags []bool
	base := testRoundTripper(func(req *http.Request) (*http.Response, error) {
		flag, _ := req.Context().Value(loopbackOnlyHTTPContextKey{}).(bool)
		seenFlags = append(seenFlags, flag)
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("ok"))}, nil
	})
	rt := idleTimeoutRoundTripper{base: base, policy: policy, requestTimeout: time.Second, idleTimeout: time.Second}

	httpReq, _ := http.NewRequest(http.MethodGet, "http://rebind.localhost:8080/mcp", nil)
	resp1, err := rt.RoundTrip(httpReq)
	if err != nil {
		t.Fatalf("http localhost roundtrip: %v", err)
	}
	_ = resp1.Body.Close()

	// Simulate http.Client carrying the first request's context across a redirect to HTTPS.
	reboundCtx := contextWithLoopbackHTTPCheck(context.Background(), policy, httpReq.URL)
	httpsReq, _ := http.NewRequestWithContext(reboundCtx, http.MethodGet, "https://api.openai.com/v1/models", nil)
	resp2, err := rt.RoundTrip(httpsReq)
	if err != nil {
		t.Fatalf("https roundtrip: %v", err)
	}
	_ = resp2.Body.Close()

	if len(seenFlags) != 2 || !seenFlags[0] || seenFlags[1] {
		t.Fatalf("expected loopbackOnly flags [true, false], got %v", seenFlags)
	}

	// Verify DialContext rejects non-loopback IP literal when loopbackOnlyHTTPContextKey is active, even if allowlisted.
	client := NewHTTPClient(policy)
	wrappedRT := client.Transport.(idleTimeoutRoundTripper)
	transport := wrappedRT.base.(*http.Transport)
	ctxLoopback := contextWithLoopbackHTTPCheck(context.Background(), policy, &url.URL{Scheme: "http", Host: "rebind.localhost:8080"})
	if _, err := transport.DialContext(ctxLoopback, "tcp", "10.0.0.5:8080"); !errors.Is(err, ErrInsecureHTTPBlocked) {
		t.Fatalf("expected DialContext with loopbackOnly HTTP context to reject 10.0.0.5 with ErrInsecureHTTPBlocked, got %v", err)
	}
}
