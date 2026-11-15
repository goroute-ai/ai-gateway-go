package server

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
)

func TestDecodeChatCompletionRequestDecodesCanonicalAndExtensionFields(t *testing.T) {
	input := `{"model":"gpt-4o","messages":[{"role":"user","content":"hello"}],"temperature":0.25,"extra_body":{"seed":42,"model":"ignored"},"top_k":50}`
	var got domain.CanonicalChatRequest
	if err := decodeChatCompletionRequest(strings.NewReader(input), &got); err != nil {
		t.Fatal(err)
	}
	if got.Model != "gpt-4o" || len(got.Messages) != 1 || got.Messages[0].Content != "hello" {
		t.Fatalf("canonical fields not decoded: %+v", got)
	}
	if got.Temperature == nil || *got.Temperature != 0.25 {
		t.Fatalf("temperature = %v", got.Temperature)
	}
	if got.ExtraParams["model"] != nil {
		t.Fatalf("extra body overwrote protected model: %#v", got.ExtraParams)
	}
	if got.ExtraParams["seed"] != jsonNumber("42") || got.ExtraParams["top_k"] != jsonNumber("50") {
		t.Fatalf("extension numbers should retain exact JSON number semantics: %#v", got.ExtraParams)
	}
}

type jsonNumber = json.Number

func TestDecodeChatCompletionRequestRejectsTrailingJSON(t *testing.T) {
	var got domain.CanonicalChatRequest
	if err := decodeChatCompletionRequest(strings.NewReader(`{"model":"a"} {"model":"b"}`), &got); err == nil {
		t.Fatal("expected trailing JSON value to be rejected")
	}
}

func TestChatCompletionBodyLimitErrorRemainsDetectable(t *testing.T) {
	oversized := `{"unknown":"` + strings.Repeat("x", 20) + `"}`
	reader := http.MaxBytesReader(httptest.NewRecorder(), io.NopCloser(strings.NewReader(oversized)), 10)
	var got domain.CanonicalChatRequest
	err := decodeChatCompletionRequest(reader, &got)
	var maxErr *http.MaxBytesError
	if !errors.As(err, &maxErr) {
		t.Fatalf("decode error = %v, want MaxBytesError", err)
	}
}

func BenchmarkDecodeChatCompletionRequest(b *testing.B) {
	input := `{"model":"openai/gpt-4.1","messages":[{"role":"system","content":"Be concise."},{"role":"user","content":[{"type":"text","text":"Summarize this request."}]}],"tools":[{"type":"function","function":{"name":"lookup","parameters":{"type":"object","properties":{"query":{"type":"string"}}}}}],"temperature":0.2,"extra_body":{"seed":42,"provider_option":{"mode":"fast"}},"top_k":50}`
	b.ReportAllocs()
	b.SetBytes(int64(len(input)))
	for i := 0; i < b.N; i++ {
		var req domain.CanonicalChatRequest
		if err := decodeChatCompletionRequest(strings.NewReader(input), &req); err != nil {
			b.Fatal(err)
		}
	}
}
