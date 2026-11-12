package cache

import (
	"testing"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
)

func TestResponseCache_ComputeKeyCollisionResistance(t *testing.T) {
	rc := NewResponseCache(true, 100, nil)

	temp0 := 0.0
	temp7 := 0.7
	reqBase := &domain.CanonicalChatRequest{
		Model:       "gpt-4o",
		Temperature: &temp0,
		Messages: []domain.CanonicalMessage{
			{Role: "user", Content: "Tell me a joke"},
		},
	}

	keyBase := rc.ComputeKey("org-1", reqBase)

	// Different temperature must produce distinct key
	reqTemp := &domain.CanonicalChatRequest{
		Model:       "gpt-4o",
		Temperature: &temp7,
		Messages: []domain.CanonicalMessage{
			{Role: "user", Content: "Tell me a joke"},
		},
	}
	keyTemp := rc.ComputeKey("org-1", reqTemp)
	if keyTemp == keyBase {
		t.Fatalf("expected different cache key for different temperature")
	}

	// Different reasoning_effort must produce distinct key
	reqReasoning := &domain.CanonicalChatRequest{
		Model:           "gpt-4o",
		Temperature:     &temp0,
		ReasoningEffort: "high",
		Messages: []domain.CanonicalMessage{
			{Role: "user", Content: "Tell me a joke"},
		},
	}
	keyReasoning := rc.ComputeKey("org-1", reqReasoning)
	if keyReasoning == keyBase {
		t.Fatalf("expected different cache key for different reasoning_effort")
	}

	// Different top_p must produce distinct key
	topP := 0.8
	reqTopP := &domain.CanonicalChatRequest{
		Model:       "gpt-4o",
		Temperature: &temp0,
		TopP:        &topP,
		Messages: []domain.CanonicalMessage{
			{Role: "user", Content: "Tell me a joke"},
		},
	}
	keyTopP := rc.ComputeKey("org-1", reqTopP)
	if keyTopP == keyBase {
		t.Fatalf("expected different cache key for different top_p")
	}

	// Different org must produce distinct key
	keyOrg2 := rc.ComputeKey("org-2", reqBase)
	if keyOrg2 == keyBase {
		t.Fatalf("expected different cache key for different orgID")
	}
}

func TestResponseCache_ComputeKeyIncludesAllCanonicalOutputFields(t *testing.T) {
	rc := NewResponseCache(true, 100, nil)
	temp := 0.0
	base := &domain.CanonicalChatRequest{
		Model: "model-a", Temperature: &temp,
		Messages: []domain.CanonicalMessage{{Role: "user", Content: "hello"}},
	}
	baseKey := rc.ComputeKey("org-1", base)
	cases := map[string]func(*domain.CanonicalChatRequest){
		"metadata":       func(r *domain.CanonicalChatRequest) { r.Metadata = map[string]string{"tenant_mode": "strict"} },
		"extra_params":   func(r *domain.CanonicalChatRequest) { r.ExtraParams = map[string]any{"seed": 41} },
		"stream_options": func(r *domain.CanonicalChatRequest) { r.StreamOptions = &domain.StreamOptions{IncludeUsage: true} },
		"gateway_extensions": func(r *domain.CanonicalChatRequest) {
			r.GoRouteExtensions = &domain.GoRouteExtensions{TaskID: "task-1"}
		},
		"request_id_is_ignored": func(r *domain.CanonicalChatRequest) { r.RequestID = "request-2" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			copy := *base
			mutate(&copy)
			key := rc.ComputeKey("org-1", &copy)
			if name == "request_id_is_ignored" {
				if key != baseKey {
					t.Fatal("request ID should not fragment equivalent cache entries")
				}
				return
			}
			if key == baseKey {
				t.Fatalf("expected %s to change the response cache key", name)
			}
		})
	}
}

func TestResponseCache_ComputeKeyDisablesCachingForUnencodableRequest(t *testing.T) {
	rc := NewResponseCache(true, 100, nil)
	key := rc.ComputeKey("org-1", &domain.CanonicalChatRequest{Model: "model-a", ExtraParams: map[string]any{"invalid": func() {}}})
	if key != "" {
		t.Fatalf("expected unencodable request to disable caching, got key %q", key)
	}
}
