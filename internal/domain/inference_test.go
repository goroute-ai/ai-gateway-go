package domain

import (
	"encoding/json"
	"testing"
)

func TestCanonicalMessageUnmarshal_MultimodalContentArray(t *testing.T) {
	var message CanonicalMessage
	raw := `{"role":"user","content":[{"type":"text","text":"What is in this picture?"},{"type":"image_url","image_url":{"url":"data:image/png;base64,aGVsbG8=","detail":"high"}},{"type":"input_image","image_url":"https://example.com/picture.png"}],"cache_control":{"type":"ephemeral","ttl":"1h"}}`
	if err := json.Unmarshal([]byte(raw), &message); err != nil {
		t.Fatalf("unmarshal multimodal message: %v", err)
	}
	if message.Content != "What is in this picture?" {
		t.Fatalf("Content = %q, want text for guardrail inspection", message.Content)
	}
	if len(message.Parts) != 3 || message.Parts[1].Type != "image_url" || message.Parts[1].ImageURL == nil {
		t.Fatalf("multimodal Parts were not preserved: %+v", message.Parts)
	}
	if message.Parts[1].ImageURL.Detail != "high" {
		t.Fatalf("image detail = %q, want high", message.Parts[1].ImageURL.Detail)
	}
	if message.Parts[2].Type != "image_url" || message.Parts[2].ImageURL == nil || message.Parts[2].ImageURL.URL != "https://example.com/picture.png" {
		t.Fatalf("input_image form was not normalized: %+v", message.Parts[2])
	}
	if message.CacheControl == nil || message.CacheControl.TTL != "1h" {
		t.Fatalf("cache control was not preserved: %+v", message.CacheControl)
	}
}

func TestCanonicalMessageUnmarshal_StringContent(t *testing.T) {
	var message CanonicalMessage
	if err := json.Unmarshal([]byte(`{"role":"user","content":"hello"}`), &message); err != nil {
		t.Fatalf("unmarshal text message: %v", err)
	}
	if message.Content != "hello" || len(message.Parts) != 0 {
		t.Fatalf("unexpected string content: %+v", message)
	}
}
