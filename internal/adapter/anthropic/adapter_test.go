package anthropic

import (
	"testing"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
)

func TestToAnthropicRequest_ParallelToolResultsConsolidation(t *testing.T) {
	req := &domain.CanonicalChatRequest{
		Model: "claude-3-5-sonnet",
		Messages: []domain.CanonicalMessage{
			{Role: "user", Content: "What is the weather in Tokyo and Paris?"},
			{
				Role: "assistant",
				ToolCalls: []domain.CanonicalToolCall{
					{ID: "call_tokyo", Type: "function", Function: domain.CanonicalFunctionCall{Name: "get_weather", Arguments: `{"city":"Tokyo"}`}},
					{ID: "call_paris", Type: "function", Function: domain.CanonicalFunctionCall{Name: "get_weather", Arguments: `{"city":"Paris"}`}},
				},
			},
			{Role: "tool", ToolCallID: "call_tokyo", Content: `{"temp": 18}`},
			{Role: "tool", ToolCallID: "call_paris", Content: `{"temp": 22}`},
		},
	}

	antReq := toAnthropicRequest(req.Model, req, false)

	// We expect 3 messages: user, assistant, user (with 2 tool_result blocks)
	// Consecutive "tool" messages must be merged into one "user" turn to prevent HTTP 400 from Anthropic
	if len(antReq.Messages) != 3 {
		t.Fatalf("expected 3 messages, got %d", len(antReq.Messages))
	}

	lastMsg := antReq.Messages[2]
	if lastMsg.Role != "user" {
		t.Fatalf("expected last message role to be 'user', got %s", lastMsg.Role)
	}
	if len(lastMsg.Content) != 2 {
		t.Fatalf("expected 2 tool_result content blocks, got %d", len(lastMsg.Content))
	}
	if lastMsg.Content[0].Type != "tool_result" || lastMsg.Content[0].ToolUseID != "call_tokyo" {
		t.Fatalf("expected first content block to be call_tokyo tool_result")
	}
	if lastMsg.Content[1].Type != "tool_result" || lastMsg.Content[1].ToolUseID != "call_paris" {
		t.Fatalf("expected second content block to be call_paris tool_result")
	}
}

func TestToAnthropicRequest_ThinkingTemperatureOmission(t *testing.T) {
	temp := 0.7
	req := &domain.CanonicalChatRequest{
		Model:           "claude-3-7-sonnet",
		Temperature:     &temp,
		ReasoningEffort: "high",
		Messages: []domain.CanonicalMessage{
			{Role: "user", Content: "Solve this math problem"},
		},
	}

	antReq := toAnthropicRequest(req.Model, req, false)
	if antReq.Thinking == nil {
		t.Fatalf("expected thinking to be enabled")
	}
	if antReq.Temperature != nil {
		t.Fatalf("expected temperature to be nil when thinking is enabled, got %v", *antReq.Temperature)
	}
	if antReq.TopP != nil {
		t.Fatalf("expected top_p to be nil when thinking is enabled, got %v", *antReq.TopP)
	}
}

func TestToAnthropicRequest_AssistantPrefill(t *testing.T) {
	t.Run("preserves clean trailing assistant message", func(t *testing.T) {
		req := &domain.CanonicalChatRequest{
			Model: "claude-3-5-sonnet",
			Messages: []domain.CanonicalMessage{
				{Role: "user", Content: "Return JSON"},
				{Role: "assistant", Content: "{"},
			},
		}
		antReq := toAnthropicRequest(req.Model, req, false)
		if len(antReq.Messages) != 2 {
			t.Fatalf("expected 2 messages, got %d", len(antReq.Messages))
		}
		last := antReq.Messages[1]
		if last.Role != "assistant" || len(last.Content) != 1 || last.Content[0].Type != "text" || last.Content[0].Text != "{" {
			t.Fatalf("unexpected trailing assistant message: %+v", last)
		}
	})

	t.Run("trims trailing whitespace on final assistant prefill", func(t *testing.T) {
		req := &domain.CanonicalChatRequest{
			Model: "claude-3-5-sonnet",
			Messages: []domain.CanonicalMessage{
				{Role: "user", Content: "First"},
				{Role: "assistant", Content: "Intermediate reply   "},
				{Role: "user", Content: "Continue"},
				{Role: "assistant", Content: "The answer is: \t\n "},
			},
		}
		antReq := toAnthropicRequest(req.Model, req, false)
		if len(antReq.Messages) != 4 {
			t.Fatalf("expected 4 messages, got %d", len(antReq.Messages))
		}
		if antReq.Messages[1].Content[0].Text != "Intermediate reply   " {
			t.Fatalf("non-trailing assistant message must remain untouched, got %q", antReq.Messages[1].Content[0].Text)
		}
		if antReq.Messages[3].Role != "assistant" || antReq.Messages[3].Content[0].Text != "The answer is:" {
			t.Fatalf("expected trimmed trailing assistant prefill, got %+v", antReq.Messages[3])
		}
	})

	t.Run("omits whitespace-only trailing assistant prefill", func(t *testing.T) {
		req := &domain.CanonicalChatRequest{
			Model: "claude-3-5-sonnet",
			Messages: []domain.CanonicalMessage{
				{Role: "user", Content: "Hello"},
				{Role: "assistant", Content: "   \n\t"},
			},
		}
		antReq := toAnthropicRequest(req.Model, req, false)
		if len(antReq.Messages) != 1 {
			t.Fatalf("expected whitespace-only trailing assistant message to be omitted, got %d messages: %+v", len(antReq.Messages), antReq.Messages)
		}
		if antReq.Messages[0].Role != "user" {
			t.Fatalf("expected user message, got %+v", antReq.Messages[0])
		}
	})
}
