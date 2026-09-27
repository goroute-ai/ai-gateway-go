package router

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
)

func makeTextChunk(content string) *domain.CanonicalStreamChunk {
	return &domain.CanonicalStreamChunk{
		ID:     "chunk-1",
		Object: "chat.completion.chunk",
		Choices: []domain.CanonicalStreamChoice{
			{
				Index: 0,
				Delta: domain.CanonicalStreamDelta{
					Content: content,
				},
			},
		},
	}
}

func TestStreamContinuation_PlainTextAccumulationAndCanContinue(t *testing.T) {
	var acc streamAccumulator
	req := &domain.CanonicalChatRequest{
		Model: "gpt-4o",
		Messages: []domain.CanonicalMessage{
			{Role: "user", Content: "Tell me a story."},
		},
		Stream: true,
	}
	acc.ObserveRequest(req)
	acc.ObserveChunk(makeTextChunk("Once upon "))
	acc.ObserveChunk(makeTextChunk("a time in Go."))

	if got, want := acc.textBuf.String(), "Once upon a time in Go."; got != want {
		t.Fatalf("textBuf = %q, want %q", got, want)
	}
	if acc.emittedTokensEst <= 0 {
		t.Fatalf("emittedTokensEst = %d, want > 0", acc.emittedTokensEst)
	}
	if acc.hasNonTextOutput {
		t.Fatalf("expected hasNonTextOutput = false for plain text")
	}

	upstreamErr := &domain.GatewayError{
		StatusCode: http.StatusBadGateway,
		Type:       domain.ErrorTypeUpstream,
		Code:       "upstream_unavailable",
		Retryable:  true,
	}

	// Disabled in config.
	if acc.CanContinue(config.RouterConfig{EnableMidStreamContinuation: false}, 0, upstreamErr) {
		t.Fatalf("expected CanContinue = false when feature is disabled")
	}

	// Enabled with default MaxStreamContinuations (0 -> defaults to 1).
	cfgDefault := config.RouterConfig{EnableMidStreamContinuation: true}
	if !acc.CanContinue(cfgDefault, 0, upstreamErr) {
		t.Fatalf("expected CanContinue = true for first continuation when enabled")
	}
	if acc.CanContinue(cfgDefault, 1, upstreamErr) {
		t.Fatalf("expected CanContinue = false when continuationCount reaches default cap 1")
	}

	// Explicit MaxStreamContinuations = 2.
	cfgTwo := config.RouterConfig{EnableMidStreamContinuation: true, MaxStreamContinuations: 2}
	if !acc.CanContinue(cfgTwo, 1, io.ErrUnexpectedEOF) {
		t.Fatalf("expected CanContinue = true for second continuation when max=2")
	}
	if acc.CanContinue(cfgTwo, 2, io.ErrUnexpectedEOF) {
		t.Fatalf("expected CanContinue = false when continuationCount reaches max=2")
	}
	if acc.CanContinue(cfgTwo, -1, io.ErrUnexpectedEOF) {
		t.Fatalf("expected CanContinue = false for negative continuationCount")
	}
	if acc.CanContinue(config.RouterConfig{EnableMidStreamContinuation: true, MaxStreamContinuations: -1}, 0, io.ErrUnexpectedEOF) {
		t.Fatalf("expected CanContinue = false for negative MaxStreamContinuations")
	}

	// Empty buffer cannot continue.
	var emptyAcc streamAccumulator
	if emptyAcc.CanContinue(cfgTwo, 0, io.ErrUnexpectedEOF) {
		t.Fatalf("expected CanContinue = false when no text was emitted")
	}
}

func TestStreamContinuation_BufferOverflowGate(t *testing.T) {
	cfg := config.RouterConfig{
		EnableMidStreamContinuation: true,
		MaxStreamContinuations:      2,
	}
	upstreamErr := io.ErrUnexpectedEOF

	// Exact 256 KiB cap is allowed.
	var exactAcc streamAccumulator
	exactPayload := strings.Repeat("a", maxStreamContinuationBufferBytes)
	exactAcc.ObserveChunk(makeTextChunk(exactPayload))
	if exactAcc.overflowed {
		t.Fatalf("expected overflowed = false at exact 256 KiB cap")
	}
	if exactAcc.textBuf.Len() != maxStreamContinuationBufferBytes {
		t.Fatalf("textBuf.Len() = %d, want %d", exactAcc.textBuf.Len(), maxStreamContinuationBufferBytes)
	}
	if !exactAcc.CanContinue(cfg, 0, upstreamErr) {
		t.Fatalf("expected CanContinue = true at exact 256 KiB cap")
	}

	// 1 byte over 256 KiB trips overflowed and bounds textBuf.
	exactAcc.ObserveChunk(makeTextChunk("b"))
	if !exactAcc.overflowed {
		t.Fatalf("expected overflowed = true when exceeding 256 KiB cap")
	}
	if exactAcc.textBuf.Len() > maxStreamContinuationBufferBytes {
		t.Fatalf("textBuf.Len() = %d exceeded cap %d", exactAcc.textBuf.Len(), maxStreamContinuationBufferBytes)
	}
	if exactAcc.CanContinue(cfg, 0, upstreamErr) {
		t.Fatalf("expected CanContinue = false after buffer overflow")
	}
}

func TestStreamContinuation_NonTextRefusals(t *testing.T) {
	cfg := config.RouterConfig{
		EnableMidStreamContinuation: true,
		MaxStreamContinuations:      2,
	}
	upstreamErr := io.ErrUnexpectedEOF

	t.Run("json_object_response_format", func(t *testing.T) {
		var acc streamAccumulator
		acc.ObserveRequest(&domain.CanonicalChatRequest{
			ResponseFormat: &domain.ResponseFormat{Type: "json_object"},
		})
		acc.ObserveChunk(makeTextChunk(`{"a":`))
		if acc.CanContinue(cfg, 0, upstreamErr) {
			t.Fatalf("expected refusal for json_object response_format")
		}
	})

	t.Run("json_schema_response_format", func(t *testing.T) {
		var acc streamAccumulator
		acc.ObserveRequest(&domain.CanonicalChatRequest{
			ResponseFormat: &domain.ResponseFormat{
				Type:       "json_schema",
				JSONSchema: map[string]any{"type": "object"},
			},
		})
		acc.ObserveChunk(makeTextChunk(`{"a":`))
		if acc.CanContinue(cfg, 0, upstreamErr) {
			t.Fatalf("expected refusal for json_schema response_format")
		}
	})

	t.Run("text_response_format_allowed", func(t *testing.T) {
		var acc streamAccumulator
		acc.ObserveRequest(&domain.CanonicalChatRequest{
			ResponseFormat: &domain.ResponseFormat{Type: "text"},
		})
		acc.ObserveChunk(makeTextChunk("hello"))
		if !acc.CanContinue(cfg, 0, upstreamErr) {
			t.Fatalf("expected text response_format to allow continuation")
		}
	})

	t.Run("forced_tool_choice_variants", func(t *testing.T) {
		forcedChoices := []any{
			"required",
			"any",
			map[string]any{"type": "function", "function": map[string]any{"name": "get_weather"}},
			map[string]any{"type": "tool", "name": "get_weather"},
		}
		for i, tc := range forcedChoices {
			var acc streamAccumulator
			acc.ObserveRequest(&domain.CanonicalChatRequest{ToolChoice: tc})
			acc.ObserveChunk(makeTextChunk("partial"))
			if acc.CanContinue(cfg, 0, upstreamErr) {
				t.Fatalf("case %d (%v): expected refusal for forced tool_choice", i, tc)
			}
		}

		allowedChoices := []any{
			nil,
			"auto",
			"none",
			map[string]any{"type": "auto"},
			map[string]any{"type": "none"},
		}
		for i, tc := range allowedChoices {
			var acc streamAccumulator
			acc.ObserveRequest(&domain.CanonicalChatRequest{ToolChoice: tc})
			acc.ObserveChunk(makeTextChunk("partial"))
			if !acc.CanContinue(cfg, 0, upstreamErr) {
				t.Fatalf("case %d (%v): expected non-forced tool_choice to allow continuation", i, tc)
			}
		}
	})

	t.Run("delta_tool_calls", func(t *testing.T) {
		var acc streamAccumulator
		acc.ObserveChunk(makeTextChunk("Calling tool..."))
		acc.ObserveChunk(&domain.CanonicalStreamChunk{
			Choices: []domain.CanonicalStreamChoice{
				{
					Index: 0,
					Delta: domain.CanonicalStreamDelta{
						ToolCalls: []domain.CanonicalToolCall{
							{
								ID:   "call_1",
								Type: "function",
								Function: domain.CanonicalFunctionCall{
									Name:      "lookup",
									Arguments: `{"q":`,
								},
							},
						},
					},
				},
			},
		})
		if acc.CanContinue(cfg, 0, upstreamErr) {
			t.Fatalf("expected refusal when chunk contains tool_calls")
		}
	})

	t.Run("delta_reasoning_content", func(t *testing.T) {
		var acc streamAccumulator
		acc.ObserveChunk(&domain.CanonicalStreamChunk{
			Choices: []domain.CanonicalStreamChoice{
				{
					Index: 0,
					Delta: domain.CanonicalStreamDelta{
						ReasoningContent: "Let me think step by step...",
					},
				},
			},
		})
		acc.ObserveChunk(makeTextChunk("Answer: "))
		if acc.CanContinue(cfg, 0, upstreamErr) {
			t.Fatalf("expected refusal when chunk contains reasoning_content")
		}
	})
}

func TestStreamContinuation_ErrorClassificationAndContextCanceled(t *testing.T) {
	cfg := config.RouterConfig{
		EnableMidStreamContinuation: true,
		MaxStreamContinuations:      2,
	}

	var acc streamAccumulator
	acc.ObserveChunk(makeTextChunk("Some streamed text"))

	refused := []struct {
		name string
		err  error
	}{
		{name: "nil_error", err: nil},
		{name: "context_canceled", err: context.Canceled},
		{name: "wrapped_context_canceled", err: fmt.Errorf("stream aborted: %w", context.Canceled)},
		{
			name: "non_retryable_client_error",
			err: &domain.GatewayError{
				StatusCode: http.StatusBadRequest,
				Type:       domain.ErrorTypeInvalidRequest,
				Code:       "invalid_request",
				Retryable:  false,
			},
		},
		{
			name: "guardrail_blocked_error",
			err: &domain.GatewayError{
				StatusCode: http.StatusBadGateway,
				Type:       domain.ErrorTypeServer,
				Code:       "guardrail_blocked",
				Retryable:  false,
			},
		},
		{
			name: "guardrail_output_blocked_even_if_marked_retryable",
			err: &domain.GatewayError{
				StatusCode: http.StatusBadGateway,
				Type:       domain.ErrorTypeServer,
				Code:       "guardrail_output_blocked",
				Retryable:  true,
			},
		},
		{
			name: "auth_failure",
			err: &domain.GatewayError{
				StatusCode:  http.StatusBadGateway,
				Type:        domain.ErrorTypeAuthentication,
				Code:        "upstream_auth_error",
				AuthFailure: true,
				Retryable:   false,
			},
		},
	}

	for _, tc := range refused {
		t.Run("refuse_"+tc.name, func(t *testing.T) {
			if acc.CanContinue(cfg, 0, tc.err) {
				t.Fatalf("expected CanContinue = false for %v", tc.err)
			}
		})
	}

	allowed := []struct {
		name string
		err  error
	}{
		{name: "unexpected_eof", err: io.ErrUnexpectedEOF},
		{name: "raw_transport_error", err: errors.New("connection reset by peer")},
		{name: "deadline_exceeded", err: context.DeadlineExceeded},
		{
			name: "retryable_upstream_502",
			err: &domain.GatewayError{
				StatusCode: http.StatusBadGateway,
				Type:       domain.ErrorTypeUpstream,
				Code:       "upstream_unavailable",
				Retryable:  true,
			},
		},
		{
			name: "retryable_rate_limit_429",
			err: &domain.GatewayError{
				StatusCode: http.StatusTooManyRequests,
				Type:       domain.ErrorTypeRateLimit,
				Code:       "upstream_rate_limit",
				Retryable:  true,
			},
		},
	}

	for _, tc := range allowed {
		t.Run("allow_"+tc.name, func(t *testing.T) {
			if !acc.CanContinue(cfg, 0, tc.err) {
				t.Fatalf("expected CanContinue = true for %v", tc.err)
			}
		})
	}
}

func TestStreamContinuation_BuildContinuationRequestAndMaxTokensBudget(t *testing.T) {
	t.Run("clones_messages_and_decrements_max_tokens", func(t *testing.T) {
		var acc streamAccumulator
		// 40 ASCII chars -> emittedTokensEst = 10.
		acc.ObserveChunk(makeTextChunk("0123456789012345678901234567890123456789"))
		if acc.emittedTokensEst != 10 {
			t.Fatalf("emittedTokensEst = %d, want 10", acc.emittedTokensEst)
		}

		origMax := 25
		origReq := &domain.CanonicalChatRequest{
			Model: "claude-3-7-sonnet",
			Messages: []domain.CanonicalMessage{
				{Role: "system", Content: "Be concise."},
				{Role: "user", Content: "Count to 20."},
			},
			MaxTokens: &origMax,
			Stream:    true,
		}

		contReq, ok := acc.BuildContinuationRequest(origReq)
		if !ok || contReq == nil {
			t.Fatalf("expected BuildContinuationRequest to succeed")
		}

		// Original request must remain unmodified.
		if len(origReq.Messages) != 2 {
			t.Fatalf("original Messages mutated: len=%d", len(origReq.Messages))
		}
		if *origReq.MaxTokens != 25 {
			t.Fatalf("original MaxTokens mutated: got %d, want 25", *origReq.MaxTokens)
		}

		if len(contReq.Messages) != 3 {
			t.Fatalf("contReq.Messages len = %d, want 3", len(contReq.Messages))
		}
		last := contReq.Messages[2]
		if last.Role != "assistant" || last.Content != "0123456789012345678901234567890123456789" {
			t.Fatalf("unexpected prefill message: %+v", last)
		}
		if contReq.MaxTokens == nil || *contReq.MaxTokens != 15 {
			t.Fatalf("contReq.MaxTokens = %v, want 15", contReq.MaxTokens)
		}
	})

	t.Run("exhausted_max_tokens_returns_false_for_clean_completion", func(t *testing.T) {
		var acc streamAccumulator
		acc.ObserveChunk(makeTextChunk("0123456789012345678901234567890123456789")) // est 10

		for _, maxTok := range []int{10, 5, 0} {
			m := maxTok
			req := &domain.CanonicalChatRequest{
				Model:     "gpt-4o",
				Messages:  []domain.CanonicalMessage{{Role: "user", Content: "hi"}},
				MaxTokens: &m,
			}
			contReq, ok := acc.BuildContinuationRequest(req)
			if ok || contReq != nil {
				t.Fatalf("maxTok=%d: expected (nil, false) when budget <= 0, got (%v, %v)", maxTok, contReq, ok)
			}
		}
	})

	t.Run("remaining_one_floors_at_one", func(t *testing.T) {
		var acc streamAccumulator
		acc.ObserveChunk(makeTextChunk("0123456789012345678901234567890123456789")) // est 10
		maxTok := 11
		req := &domain.CanonicalChatRequest{
			Model:     "gpt-4o",
			Messages:  []domain.CanonicalMessage{{Role: "user", Content: "hi"}},
			MaxTokens: &maxTok,
		}
		contReq, ok := acc.BuildContinuationRequest(req)
		if !ok || contReq == nil || contReq.MaxTokens == nil || *contReq.MaxTokens != 1 {
			t.Fatalf("expected MaxTokens=1, got ok=%v contReq=%+v", ok, contReq)
		}
	})

	t.Run("nil_max_tokens_stays_nil", func(t *testing.T) {
		var acc streamAccumulator
		acc.ObserveChunk(makeTextChunk("hello"))
		req := &domain.CanonicalChatRequest{
			Model:    "gpt-4o",
			Messages: []domain.CanonicalMessage{{Role: "user", Content: "hi"}},
		}
		contReq, ok := acc.BuildContinuationRequest(req)
		if !ok || contReq == nil {
			t.Fatalf("expected BuildContinuationRequest to succeed")
		}
		if contReq.MaxTokens != nil {
			t.Fatalf("expected MaxTokens to remain nil, got %d", *contReq.MaxTokens)
		}
	})
}

func TestStreamContinuation_MergeUsage(t *testing.T) {
	t.Run("nil_and_single_sided_inputs", func(t *testing.T) {
		var acc streamAccumulator
		if got := acc.MergeUsage(nil, nil); got != nil {
			t.Fatalf("expected nil, got %+v", got)
		}

		final := &domain.TokenUsage{PromptTokens: 12, CompletionTokens: 8, TotalTokens: 20}
		gotFinal := acc.MergeUsage(nil, final)
		if gotFinal == nil || *gotFinal != *final || gotFinal == final {
			t.Fatalf("expected copy of final, got %+v", gotFinal)
		}

		partial := &domain.TokenUsage{PromptTokens: 10, CompletionTokens: 5, TotalTokens: 15}
		gotPartial := acc.MergeUsage(partial, nil)
		if gotPartial == nil || *gotPartial != *partial || gotPartial == partial {
			t.Fatalf("expected copy of partial, got %+v", gotPartial)
		}
	})

	t.Run("combines_partial_and_final_usage", func(t *testing.T) {
		var acc streamAccumulator
		partial := &domain.TokenUsage{
			PromptTokens:        100,
			CompletionTokens:    25,
			TotalTokens:         125,
			CachedPromptTokens:  40,
			CacheCreationTokens: 10,
			ReasoningTokens:     3,
		}
		final := &domain.TokenUsage{
			PromptTokens:        125,
			CompletionTokens:    30,
			TotalTokens:         155,
			CachedPromptTokens:  90,
			CacheCreationTokens: 0,
			ReasoningTokens:     2,
		}
		merged := acc.MergeUsage(partial, final)
		want := domain.TokenUsage{
			PromptTokens:        225,
			CompletionTokens:    55,
			TotalTokens:         280,
			CachedPromptTokens:  130,
			CacheCreationTokens: 10,
			ReasoningTokens:     5,
		}
		if merged == nil || *merged != want {
			t.Fatalf("merged = %+v, want %+v", merged, want)
		}
	})

	t.Run("accumulates_chunk_snapshots_without_double_counting", func(t *testing.T) {
		var acc streamAccumulator
		acc.ObserveChunk(&domain.CanonicalStreamChunk{
			Choices: []domain.CanonicalStreamChoice{{Delta: domain.CanonicalStreamDelta{Content: "part1 "}}},
			Usage:   &domain.TokenUsage{PromptTokens: 50, CachedPromptTokens: 20},
		})
		acc.ObserveChunk(&domain.CanonicalStreamChunk{
			Choices: []domain.CanonicalStreamChoice{{Delta: domain.CanonicalStreamDelta{Content: "part2"}}},
			Usage:   &domain.TokenUsage{PromptTokens: 50, CompletionTokens: 12, TotalTokens: 62},
		})

		final := &domain.TokenUsage{PromptTokens: 62, CompletionTokens: 18, TotalTokens: 80}
		merged := acc.MergeUsage(nil, final)
		want := domain.TokenUsage{
			PromptTokens:       112,
			CompletionTokens:   30,
			TotalTokens:        142,
			CachedPromptTokens: 20,
		}
		if merged == nil || *merged != want {
			t.Fatalf("merged = %+v, want %+v", merged, want)
		}
	})
}
