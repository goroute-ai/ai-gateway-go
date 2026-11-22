package adapter

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/security/network"
)

// StreamChunkHandler is invoked for each normalized OpenAI-compatible SSE chunk received from an upstream provider.
type StreamChunkHandler func(chunk *domain.CanonicalStreamChunk) error

// StreamingContext marks upstream requests made by direct adapter callers as
// streams so the shared network client applies an idle timeout without a total
// request deadline.
func StreamingContext(ctx context.Context) context.Context {
	return network.WithStreamingRequest(ctx)
}

// ProviderAdapter defines the unified contract every upstream LLM provider adapter implements.
type ProviderAdapter interface {
	Provider() domain.ProviderType
	ChatCompletion(ctx context.Context, dep *domain.Deployment, req *domain.CanonicalChatRequest) (*domain.CanonicalChatResponse, error)
	StreamChatCompletion(ctx context.Context, dep *domain.Deployment, req *domain.CanonicalChatRequest, onChunk StreamChunkHandler) (*domain.TokenUsage, error)
	Embeddings(ctx context.Context, dep *domain.Deployment, req *domain.CanonicalEmbeddingRequest) (*domain.CanonicalEmbeddingResponse, error)
	ListModels(ctx context.Context, cred *domain.ProviderCredential) ([]domain.DiscoveredModel, error)
}

// ModerationAdapter is implemented by providers supporting content safety moderation (e.g. OpenAI).
type ModerationAdapter interface {
	Moderate(ctx context.Context, dep *domain.Deployment, req *domain.CanonicalModerationRequest) (*domain.CanonicalModerationResponse, error)
}

// ImageAdapter is implemented by providers supporting image generation and editing (e.g. OpenAI).
type ImageAdapter interface {
	GenerateImage(ctx context.Context, dep *domain.Deployment, req *domain.CanonicalImageRequest) (*domain.CanonicalImageResponse, error)
}

// AudioAdapter is implemented by providers supporting audio transcription (STT) and speech generation (TTS).
type AudioAdapter interface {
	TranscribeAudio(ctx context.Context, dep *domain.Deployment, req *domain.CanonicalAudioTranscriptionRequest) (*domain.CanonicalAudioResponse, error)
	GenerateSpeech(ctx context.Context, dep *domain.Deployment, req *domain.CanonicalAudioSpeechRequest) (io.ReadCloser, string, error)
}

// CompletionAdapter is implemented by providers supporting legacy text completion models.
type CompletionAdapter interface {
	TextCompletion(ctx context.Context, dep *domain.Deployment, req *domain.CanonicalCompletionRequest) (*domain.CanonicalCompletionResponse, error)
}

// StreamingCompletionAdapter is optionally implemented by providers supporting streaming text completions.
type StreamingCompletionAdapter interface {
	StreamTextCompletion(ctx context.Context, dep *domain.Deployment, req *domain.CanonicalCompletionRequest) (<-chan domain.CanonicalStreamChunk, error)
}

// OperationSupportChecker is optionally implemented by adapters that declare
// explicit per-operation wire support (e.g. OpenAI-compatible dialect profiles).
type OperationSupportChecker interface {
	SupportsOperation(op domain.OperationType) bool
}

// PrefillSupportChecker is optionally implemented by adapters that support
// continuing generation from a trailing assistant message (assistant prefill).
type PrefillSupportChecker interface {
	SupportsAssistantPrefill() bool
}

// SupportsAssistantPrefill reports whether adp supports continuing from a
// trailing assistant message. Adapters that do not implement
// PrefillSupportChecker return false.
func SupportsAssistantPrefill(adp ProviderAdapter) bool {
	if adp == nil {
		return false
	}
	if chk, ok := adp.(PrefillSupportChecker); ok {
		return chk.SupportsAssistantPrefill()
	}
	return false
}

// NewPooledHTTPClient returns a high-concurrency HTTP client tuned for upstream LLM API connections.
func NewPooledHTTPClient(timeout time.Duration) *http.Client {
	if timeout <= 0 {
		timeout = 120 * time.Second
	}
	// Adapter fallbacks must obey the same SSRF and streaming rules as the
	// gateway's configured provider client.
	return network.NewHTTPClientWithTimeouts(nil, timeout, 2*time.Minute, 2*time.Minute, nil)
}

const (
	// DefaultMaxResponseBytes caps buffered upstream JSON/media responses (32 MiB).
	DefaultMaxResponseBytes int64 = 32 << 20
	// DefaultMaxErrorBytes caps buffered upstream error response bodies (64 KiB).
	DefaultMaxErrorBytes int64 = 64 << 10
)

// ReadBoundedBody reads at most maxBytes from r. If the body exceeds maxBytes,
// it returns a structured *domain.GatewayError with StatusBadGateway.
func ReadBoundedBody(r io.Reader, maxBytes int64, provider domain.ProviderType) ([]byte, error) {
	if r == nil {
		return nil, nil
	}
	if maxBytes <= 0 {
		maxBytes = DefaultMaxResponseBytes
	}
	data, err := io.ReadAll(io.LimitReader(r, maxBytes+1))
	if err != nil {
		return nil, &domain.GatewayError{
			StatusCode: http.StatusBadGateway,
			Type:       domain.ErrorTypeUpstream,
			Code:       "upstream_read_error",
			Message:    fmt.Sprintf("failed to read upstream response: %v", err),
			Provider:   provider,
			Retryable:  true,
		}
	}
	if int64(len(data)) > maxBytes {
		return nil, &domain.GatewayError{
			StatusCode: http.StatusBadGateway,
			Type:       domain.ErrorTypeUpstream,
			Code:       "upstream_response_too_large",
			Message:    fmt.Sprintf("upstream response exceeded %d byte limit", maxBytes),
			Provider:   provider,
			Retryable:  false,
		}
	}
	return data, nil
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

// DynamicAdapterResolver resolves custom or lazily-configured ProviderAdapters by provider type.
type DynamicAdapterResolver func(p domain.ProviderType) (ProviderAdapter, bool)

// Registry manages registered ProviderAdapters by ProviderType.
type Registry struct {
	mu              sync.RWMutex
	adapters        map[domain.ProviderType]ProviderAdapter
	dynamicResolver DynamicAdapterResolver
}

// NewRegistry initializes an empty provider adapter Registry.
func NewRegistry() *Registry {
	return &Registry{
		adapters: make(map[domain.ProviderType]ProviderAdapter),
	}
}

// SetDynamicResolver registers a fallback resolver consulted when a provider is absent from the static map.
func (r *Registry) SetDynamicResolver(resolver DynamicAdapterResolver) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.dynamicResolver = resolver
}

// Register adds or replaces a ProviderAdapter keyed by its Provider() identifier.
func (r *Registry) Register(a ProviderAdapter) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.adapters[a.Provider()] = a
}

// Get returns the ProviderAdapter registered for p, falling back to the dynamic resolver if configured.
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

// All returns a snapshot slice of all statically registered ProviderAdapters.
func (r *Registry) All() []ProviderAdapter {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]ProviderAdapter, 0, len(r.adapters))
	for _, a := range r.adapters {
		out = append(out, a)
	}
	return out
}
