package openaicompat

import (
	"encoding/json"
	"testing"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
)

func TestBuildUpstreamPayload_ExtraParams(t *testing.T) {
	adp := NewAdapter(&DialectProfile{}, nil)

	req := &domain.CanonicalChatRequest{
		Model: "llama-3.3-70b-versatile",
		Messages: []domain.CanonicalMessage{
			{Role: "user", Content: "hi"},
		},
		ExtraParams: map[string]any{
			"seed":               42,
			"repetition_penalty": 1.1,
			"model":              "evil-override",
			"messages":           []string{"clobber"},
			"stream":             true,
		},
	}

	raw, err := adp.buildUpstreamPayload(req, "llama-3.3-70b-versatile", false)
	if err != nil {
		t.Fatalf("buildUpstreamPayload failed: %v", err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	if decoded["model"] != "llama-3.3-70b-versatile" {
		t.Fatalf("model was clobbered: %v", decoded["model"])
	}
	if decoded["stream"] != false {
		t.Fatalf("stream was clobbered: %v", decoded["stream"])
	}
	if decoded["seed"] != float64(42) {
		t.Fatalf("expected seed=42, got %v", decoded["seed"])
	}
	if decoded["repetition_penalty"] != 1.1 {
		t.Fatalf("expected repetition_penalty=1.1, got %v", decoded["repetition_penalty"])
	}
}
