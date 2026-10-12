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
