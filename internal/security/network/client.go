package network

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/config"
)

// NewHTTPClient returns an *http.Client configured with strict outbound SSRF controls,
// disabled ambient proxying (Proxy: nil), DNS rebinding pinning, and redirect re-validation.
func NewHTTPClient(policy *Policy) *http.Client {
	return NewHTTPClientWithOptions(policy, DefaultHTTPClientOptions(), nil)
}

// HTTPClientOptions controls upstream request timing and idle-pool retention.
// Pool sizes are tunable so production measurements can guide adjustments.
type HTTPClientOptions struct {
	RequestTimeout        time.Duration
	ResponseHeaderTimeout time.Duration
	StreamIdleTimeout     time.Duration
	MaxIdleConns          int
	MaxIdleConnsPerHost   int
}

func DefaultHTTPClientOptions() HTTPClientOptions {
	return HTTPClientOptions{
		RequestTimeout:        2 * time.Minute,
		ResponseHeaderTimeout: 2 * time.Minute,
		StreamIdleTimeout:     2 * time.Minute,
		MaxIdleConns:          256,
		MaxIdleConnsPerHost:   16,
	}
}

// HTTPClientMetrics exposes low-cardinality upstream transport measurements.
type HTTPClientMetrics struct {
	requests           atomic.Uint64
	dialAttempts       atomic.Uint64
	tlsHandshakes      atomic.Uint64
	freshConnections   atomic.Uint64
	reusedConnections  atomic.Uint64
	http1Responses     atomic.Uint64
	http2Responses     atomic.Uint64
	firstByteWaitNanos atomic.Uint64
	firstByteWaitCount atomic.Uint64
	idleTimeouts       atomic.Uint64
}

type HTTPClientMetricsSnapshot struct {
	Requests           uint64
	DialAttempts       uint64
	TLSHandshakes      uint64
	FreshConnections   uint64
	ReusedConnections  uint64
	HTTP1Responses     uint64
	HTTP2Responses     uint64
	FirstByteWaitNanos uint64
	FirstByteWaitCount uint64
	IdleTimeouts       uint64
}

func NewHTTPClientMetrics() *HTTPClientMetrics { return &HTTPClientMetrics{} }

func (m *HTTPClientMetrics) Snapshot() HTTPClientMetricsSnapshot {
	if m == nil {
		return HTTPClientMetricsSnapshot{}
	}
	return HTTPClientMetricsSnapshot{
		Requests:           m.requests.Load(),
		DialAttempts:       m.dialAttempts.Load(),
		TLSHandshakes:      m.tlsHandshakes.Load(),
		FreshConnections:   m.freshConnections.Load(),
		ReusedConnections:  m.reusedConnections.Load(),
		HTTP1Responses:     m.http1Responses.Load(),
		HTTP2Responses:     m.http2Responses.Load(),
		FirstByteWaitNanos: m.firstByteWaitNanos.Load(),
		FirstByteWaitCount: m.firstByteWaitCount.Load(),
		IdleTimeouts:       m.idleTimeouts.Load(),
	}
}

// NewHTTPClientWithStats constructs the same SSRF-restricted client as
// NewHTTPClient and optionally records protocol, connection-reuse, and
// response-header timing counters.
func NewHTTPClientWithStats(policy *Policy, stats *HTTPClientMetrics) *http.Client {
	return NewHTTPClientWithOptions(policy, DefaultHTTPClientOptions(), stats)
}

// WithStreamingRequest marks a request as a long-lived stream. Streaming calls
// retain the body idle timeout but do not receive a total request deadline.
func WithStreamingRequest(ctx context.Context) context.Context {
	return context.WithValue(ctx, streamingRequestContextKey{}, true)
}

type streamingRequestContextKey struct{}

// NewHTTPClientWithTimeouts constructs the SSRF-restricted client with separate
// total request, response-header, and response-body idle timeouts. A total
// timeout applies only to non-streaming requests.
func NewHTTPClientWithTimeouts(policy *Policy, requestTimeout, responseHeaderTimeout, streamIdleTimeout time.Duration, stats *HTTPClientMetrics) *http.Client {
	options := DefaultHTTPClientOptions()
	options.RequestTimeout = requestTimeout
	options.ResponseHeaderTimeout = responseHeaderTimeout
	options.StreamIdleTimeout = streamIdleTimeout
	return NewHTTPClientWithOptions(policy, options, stats)
}

// NewHTTPClientWithOptions constructs the SSRF-restricted client with an
// explicit timeout and connection-pool configuration.
func NewHTTPClientWithOptions(policy *Policy, options HTTPClientOptions, stats *HTTPClientMetrics) *http.Client {
	defaults := DefaultHTTPClientOptions()
	if options.RequestTimeout <= 0 {
		options.RequestTimeout = defaults.RequestTimeout
	}
	if options.ResponseHeaderTimeout <= 0 {
		options.ResponseHeaderTimeout = defaults.ResponseHeaderTimeout
	}
	if options.StreamIdleTimeout <= 0 {
		options.StreamIdleTimeout = defaults.StreamIdleTimeout
	}
	if options.MaxIdleConns <= 0 {
		options.MaxIdleConns = defaults.MaxIdleConns
	}
	if options.MaxIdleConnsPerHost <= 0 {
		options.MaxIdleConnsPerHost = defaults.MaxIdleConnsPerHost
	}
	if policy == nil {
		policy, _ = NewPolicy(config.OutboundSSRFConfig{})
	}

	resolver := NewSafeResolver(policy)

	dialer := &net.Dialer{
		Timeout:   policy.DialTimeout,
		KeepAlive: 30 * time.Second,
		Control: func(network, address string, c syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				host = address
			}
			if ip := net.ParseIP(host); ip != nil {
				return policy.ValidateIP(ip)
			}
			return nil
		},
	}

	var proxyFunc func(*http.Request) (*url.URL, error)
	if policy.EgressProxyURL != "" {
		if proxyURL, err := url.Parse(policy.EgressProxyURL); err == nil {
			proxyFunc = http.ProxyURL(proxyURL)
		}
	}

	transport := &http.Transport{
		// Ambient proxies (HTTP_PROXY, HTTPS_PROXY) are disabled to prevent proxy-based SSRF bypass;
		// explicit egress proxy can be configured via policy.EgressProxyURL
		Proxy: proxyFunc,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, fmt.Errorf("network: split addr %q: %w", addr, err)
			}

			validIPs, err := resolver.LookupAndValidate(ctx, host)
			if err != nil {
				return nil, err
			}

			// Connect to the first validated IP to prevent DNS rebinding races
			var lastErr error
			for _, ip := range validIPs {
				targetAddr := net.JoinHostPort(ip.String(), port)
				if stats != nil {
					stats.dialAttempts.Add(1)
				}
				conn, err := dialer.DialContext(ctx, network, targetAddr)
				if err == nil {
					return conn, nil
				}
				lastErr = err
			}
			return nil, fmt.Errorf("network: dial failed: %w", lastErr)
		},
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          options.MaxIdleConns,
		MaxIdleConnsPerHost:   options.MaxIdleConnsPerHost,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: options.ResponseHeaderTimeout,
		ExpectContinueTimeout: 1 * time.Second,
	}

	client := &http.Client{
		// A client-wide timeout includes response-body reads and truncates healthy
		// model streams. Bound connect/TLS/response-header waits on the transport;
		// the body wrapper below enforces an idle timeout while allowing a stream
		// to run for as long as it continues to make progress.
		Transport: idleTimeoutRoundTripper{base: transport, requestTimeout: options.RequestTimeout, idleTimeout: options.StreamIdleTimeout, stats: stats},
		Timeout:   0,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= policy.MaxRedirects {
				return ErrTooManyRedirects
			}
			// Re-validate the target URL on every redirect
			if err := policy.ValidateURL(req.URL); err != nil {
				return fmt.Errorf("network: redirect target forbidden: %w", err)
			}
			return nil
		},
	}

	return client
}

// idleTimeoutRoundTripper applies total deadlines to ordinary calls and bounds
// periods with no upstream body progress for all calls, including streams.
type idleTimeoutRoundTripper struct {
	base           http.RoundTripper
	requestTimeout time.Duration
	idleTimeout    time.Duration
	stats          *HTTPClientMetrics
}

func (rt idleTimeoutRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	streaming, _ := req.Context().Value(streamingRequestContextKey{}).(bool)
	streaming = streaming || strings.Contains(strings.ToLower(req.Header.Get("Accept")), "text/event-stream")
	ctx := req.Context()
	var cancel context.CancelFunc
	if !streaming && rt.requestTimeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, rt.requestTimeout)
	} else {
		ctx, cancel = context.WithCancel(ctx)
	}
	started := time.Now()
	if rt.stats != nil {
		rt.stats.requests.Add(1)
		trace := &httptrace.ClientTrace{
			GotConn: func(info httptrace.GotConnInfo) {
				if info.Reused {
					rt.stats.reusedConnections.Add(1)
				} else {
					rt.stats.freshConnections.Add(1)
				}
			},
			GotFirstResponseByte: func() {
				rt.stats.firstByteWaitNanos.Add(uint64(time.Since(started)))
				rt.stats.firstByteWaitCount.Add(1)
			},
			TLSHandshakeDone: func(_ tls.ConnectionState, _ error) {
				rt.stats.tlsHandshakes.Add(1)
			},
		}
		ctx = httptrace.WithClientTrace(ctx, trace)
	}
	resp, err := rt.base.RoundTrip(req.Clone(ctx))
	if err != nil {
		cancel()
		return nil, err
	}
	if resp == nil || resp.Body == nil {
		cancel()
		return resp, nil
	}
	if rt.stats != nil {
		if resp.ProtoMajor == 2 {
			rt.stats.http2Responses.Add(1)
		} else {
			rt.stats.http1Responses.Add(1)
		}
	}
	resp.Body = newIdleTimeoutBody(resp.Body, cancel, rt.idleTimeout, rt.stats)
	return resp, nil
}

// idleTimeoutBody is intentionally kept separate from the request/response
// transport logic so its cancellation behavior can be exercised with a reader
// that stalls between chunks.
type idleTimeoutBody struct {
	body    io.ReadCloser
	cancel  context.CancelFunc
	reset   chan struct{}
	done    chan struct{}
	once    sync.Once
	timeout time.Duration
	stats   *HTTPClientMetrics
}

func newIdleTimeoutBody(body io.ReadCloser, cancel context.CancelFunc, timeout time.Duration, stats *HTTPClientMetrics) *idleTimeoutBody {
	b := &idleTimeoutBody{body: body, cancel: cancel, reset: make(chan struct{}, 1), done: make(chan struct{}), timeout: timeout, stats: stats}
	go b.watch()
	return b
}

func (b *idleTimeoutBody) watch() {
	timer := time.NewTimer(b.timeout)
	defer timer.Stop()
	for {
		select {
		case <-b.done:
			return
		case <-b.reset:
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			timer.Reset(b.timeout)
		case <-timer.C:
			if b.stats != nil {
				b.stats.idleTimeouts.Add(1)
			}
			b.cancel()
			return
		}
	}
}

func (b *idleTimeoutBody) Read(p []byte) (int, error) {
	n, err := b.body.Read(p)
	if n > 0 {
		select {
		case b.reset <- struct{}{}:
		default:
		}
	}
	return n, err
}

func (b *idleTimeoutBody) Close() error {
	var err error
	b.once.Do(func() {
		close(b.done)
		b.cancel()
		err = b.body.Close()
	})
	return err
}
