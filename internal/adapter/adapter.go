package adapter

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
)

// StreamChunkHandler is invoked for each normalized OpenAI-compatible SSE chunk received from an upstream provider.
type StreamChunkHandler func(chunk *domain.CanonicalStreamChunk) error

// ProviderAdapter defines the unified contract every upstream LLM provider adapter implements.
type ProviderAdapter interface {
	Provider() domain.ProviderType
	ChatCompletion(ctx context.Context, dep *domain.Deployment, req *domain.CanonicalChatRequest) (*domain.CanonicalChatResponse, error)
	StreamChatCompletion(ctx context.Context, dep *domain.Deployment, req *domain.CanonicalChatRequest, onChunk StreamChunkHandler) (*domain.TokenUsage, error)
	Embeddings(ctx context.Context, dep *domain.Deployment, req *domain.CanonicalEmbeddingRequest) (*domain.CanonicalEmbeddingResponse, error)
	ListModels(ctx context.Context, cred *domain.ProviderCredential) ([]domain.DiscoveredModel, error)
}

// NewPooledHTTPClient returns a high-concurrency HTTP client tuned for upstream LLM API connections.
func NewPooledHTTPClient(timeout time.Duration) *http.Client {
	if timeout <= 0 {
		timeout = 120 * time.Second
	}
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 60 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          1024,
		MaxIdleConnsPerHost:   256,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
	}
}

// ParseRetryAfter extracts a retry delay in seconds from an HTTP Retry-After or x-ratelimit-reset header.
func ParseRetryAfter(h http.Header) int {
	if v := strings.TrimSpace(h.Get("Retry-After")); v != "" {
		if secs, err := strconv.Atoi(v); err == nil && secs > 0 {
			return secs
		}
	}
	return 0
}

// Registry manages registered ProviderAdapters by ProviderType.
type DynamicAdapterResolver func(p domain.ProviderType) (ProviderAdapter, bool)

type Registry struct {
	mu              sync.RWMutex
	adapters        map[domain.ProviderType]ProviderAdapter
	dynamicResolver DynamicAdapterResolver
}

func NewRegistry() *Registry {
	return &Registry{
		adapters: make(map[domain.ProviderType]ProviderAdapter),
	}
}

func (r *Registry) SetDynamicResolver(resolver DynamicAdapterResolver) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.dynamicResolver = resolver
}

func (r *Registry) Register(a ProviderAdapter) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.adapters[a.Provider()] = a
}

func (r *Registry) Get(p domain.ProviderType) (ProviderAdapter, error) {
	r.mu.RLock()
	a, ok := r.adapters[p]
	resolver := r.dynamicResolver
	r.mu.RUnlock()
	if ok {
		return a, nil
	}
	if resolver != nil {
		if dyn, found := resolver(p); found && dyn != nil {
			return dyn, nil
		}
	}
	return nil, fmt.Errorf("no provider adapter registered for %q", p)
}

func (r *Registry) All() []ProviderAdapter {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]ProviderAdapter, 0, len(r.adapters))
	for _, a := range r.adapters {
		out = append(out, a)
	}
	return out
}
