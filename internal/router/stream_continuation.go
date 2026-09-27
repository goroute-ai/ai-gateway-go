package router

import (
	"context"
	"errors"
	"strings"
	"unicode/utf8"

	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
)

const (
	// maxStreamContinuationBufferBytes caps accumulated SSE assistant text at 256 KiB
	// to bound memory per in-flight stream and prevent oversized continuation prefills.
	maxStreamContinuationBufferBytes = 256 << 10
)

// streamAccumulator tracks emitted plain-text SSE output and token usage during
// a streaming chat completion so mid-stream upstream interruptions can be safely
// resumed via assistant prefill when eligible.
type streamAccumulator struct {
	textBuf          strings.Builder
	emittedTokensEst int
	totalRunes       int
	hasNonTextOutput bool
	overflowed       bool
	hasPartialUsage  bool
	partialUsage     domain.TokenUsage
}

// ObserveRequest inspects the outbound request and marks continuation ineligible
// when structured output constraints or forced tool selection are present.
func (a *streamAccumulator) ObserveRequest(req *domain.CanonicalChatRequest) {
	if a == nil || req == nil {
		return
	}
	if req.ResponseFormat != nil {
		rfType := strings.ToLower(strings.TrimSpace(req.ResponseFormat.Type))
		if rfType == "json_object" || rfType == "json_schema" || (rfType != "" && rfType != "text") || len(req.ResponseFormat.JSONSchema) > 0 {
			a.hasNonTextOutput = true
		}
	}
	if isForcedToolChoice(req.ToolChoice) {
		a.hasNonTextOutput = true
	}
}

func isForcedToolChoice(tc any) bool {
	if tc == nil {
		return false
	}
	switch v := tc.(type) {
	case string:
		norm := strings.ToLower(strings.TrimSpace(v))
		return norm != "" && norm != "auto" && norm != "none"
	case map[string]any:
		if len(v) == 0 {
			return false
		}
		if t, ok := v["type"].(string); ok {
			norm := strings.ToLower(strings.TrimSpace(t))
			if norm == "auto" || norm == "none" {
				return false
			}
		}
		return true
	default:
		return true
	}
}

// ObserveChunk inspects an emitted SSE chunk, recording plain-text delta content
// up to the 256 KiB cap, flagging non-text output (tool calls or reasoning),
// and updating partial token usage snapshots.
func (a *streamAccumulator) ObserveChunk(chunk *domain.CanonicalStreamChunk) {
	if a == nil || chunk == nil {
		return
	}
	for i := range chunk.Choices {
		choice := &chunk.Choices[i]
		delta := choice.Delta
		if len(delta.ToolCalls) > 0 || delta.ReasoningContent != "" {
			a.hasNonTextOutput = true
		}
		if choice.FinishReason != nil && *choice.FinishReason == "tool_calls" {
			a.hasNonTextOutput = true
		}
		if delta.Content != "" {
			a.totalRunes += utf8.RuneCountInString(delta.Content)
			est := a.totalRunes / 4
			if est < 1 {
				est = 1
			}
			a.emittedTokensEst = est

			if !a.overflowed {
				if a.textBuf.Len()+len(delta.Content) > maxStreamContinuationBufferBytes {
					a.overflowed = true
				} else {
					a.textBuf.WriteString(delta.Content)
				}
			}
		}
	}
	if chunk.Usage != nil {
		a.recordUsageSnapshot(chunk.Usage)
	}
}

func (a *streamAccumulator) recordUsageSnapshot(u *domain.TokenUsage) {
	if u == nil {
		return
	}
	a.hasPartialUsage = true
	if u.PromptTokens > a.partialUsage.PromptTokens {
		a.partialUsage.PromptTokens = u.PromptTokens
	}
	if u.CompletionTokens > a.partialUsage.CompletionTokens {
		a.partialUsage.CompletionTokens = u.CompletionTokens
	}
	if u.TotalTokens > a.partialUsage.TotalTokens {
		a.partialUsage.TotalTokens = u.TotalTokens
	}
	if u.CachedPromptTokens > a.partialUsage.CachedPromptTokens {
		a.partialUsage.CachedPromptTokens = u.CachedPromptTokens
	}
	if u.CacheCreationTokens > a.partialUsage.CacheCreationTokens {
		a.partialUsage.CacheCreationTokens = u.CacheCreationTokens
	}
	if u.ReasoningTokens > a.partialUsage.ReasoningTokens {
		a.partialUsage.ReasoningTokens = u.ReasoningTokens
	}
}

// CanContinue reports whether an interrupted stream is eligible for mid-stream
// continuation via assistant prefill.
func (a *streamAccumulator) CanContinue(cfg config.RouterConfig, continuationCount int, err error) bool {
	if a == nil || !cfg.EnableMidStreamContinuation {
		return false
	}
	maxContinuations := cfg.MaxStreamContinuations
	if maxContinuations < 0 {
		return false
	}
	if maxContinuations == 0 {
		maxContinuations = 1
	}
	if continuationCount < 0 || continuationCount >= maxContinuations {
		return false
	}
	if a.hasNonTextOutput || a.overflowed || a.textBuf.Len() == 0 {
		return false
	}
	return isContinuableStreamError(err)
}

func isContinuableStreamError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.Canceled) {
		return false
	}
	var gwErr *domain.GatewayError
	if errors.As(err, &gwErr) {
		if strings.HasPrefix(gwErr.Code, "guardrail_") {
			return false
		}
		if gwErr.AuthFailure || !gwErr.Retryable {
			return false
		}
		switch gwErr.Type {
		case domain.ErrorTypeInvalidRequest,
			domain.ErrorTypeAuthentication,
			domain.ErrorTypePermission,
			domain.ErrorTypeNotFound,
			domain.ErrorTypeBudgetExceeded:
			return false
		}
		return true
	}
	return true
}

// BuildContinuationRequest clones req with the accumulated assistant text
// appended as a trailing assistant prefill message and adjusts max_tokens by
// the estimated tokens already emitted. It returns (nil, false) when the
// remaining token budget is exhausted (<= 0), indicating the stream can
// complete cleanly without an upstream continuation call.
func (a *streamAccumulator) BuildContinuationRequest(req *domain.CanonicalChatRequest) (*domain.CanonicalChatRequest, bool) {
	if a == nil || req == nil {
		return nil, false
	}
	cloned := *req
	cloned.Messages = make([]domain.CanonicalMessage, len(req.Messages), len(req.Messages)+1)
	copy(cloned.Messages, req.Messages)
	cloned.Messages = append(cloned.Messages, domain.CanonicalMessage{
		Role:    "assistant",
		Content: a.textBuf.String(),
	})

	if req.MaxTokens != nil {
		remaining := *req.MaxTokens - a.emittedTokensEst
		if remaining <= 0 {
			return nil, false
		}
		if remaining < 1 {
			remaining = 1
		}
		cloned.MaxTokens = &remaining
	}
	return &cloned, true
}

// MergeUsage combines accumulated partial token usage from the interrupted
// stream attempt with usage reported by the continuation attempt.
func (a *streamAccumulator) MergeUsage(partial, final *domain.TokenUsage) *domain.TokenUsage {
	if partial == nil && a != nil && a.hasPartialUsage {
		partialCopy := a.partialUsage
		partial = &partialCopy
	}
	if partial == nil && final == nil {
		return nil
	}
	if partial == nil {
		out := *final
		return &out
	}
	if final == nil {
		out := *partial
		return &out
	}
	out := domain.TokenUsage{
		PromptTokens:        partial.PromptTokens + final.PromptTokens,
		CompletionTokens:    partial.CompletionTokens + final.CompletionTokens,
		TotalTokens:         partial.TotalTokens + final.TotalTokens,
		CachedPromptTokens:  partial.CachedPromptTokens + final.CachedPromptTokens,
		CacheCreationTokens: partial.CacheCreationTokens + final.CacheCreationTokens,
		ReasoningTokens:     partial.ReasoningTokens + final.ReasoningTokens,
	}
	if minTotal := out.PromptTokens + out.CompletionTokens; out.TotalTokens < minTotal {
		out.TotalTokens = minTotal
	}
	return &out
}
