package ratelimit

import (
	"strings"
	"testing"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
)

func BenchmarkEstimateTextTokens(b *testing.B) {
	cases := map[string]string{
		"ascii":        strings.Repeat("route model requests with a safe upper bound ", 64),
		"multilingual": strings.Repeat("請求を安全にルーティングします — запрос обрабатывается безопасно ", 32),
	}
	for name, input := range cases {
		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_ = EstimateTextTokens(input, ProfileO200K)
			}
		})
	}
}

func BenchmarkEstimateRequestTokensWithTools(b *testing.B) {
	req := &domain.CanonicalChatRequest{
		Model:    "gpt-4.1",
		Messages: []domain.CanonicalMessage{{Role: "user", Content: strings.Repeat("Please inspect this schema and respond safely. ", 32)}},
		Tools: []domain.CanonicalTool{{Type: "function", Function: domain.CanonicalFunction{
			Name:        "lookup",
			Description: "Search records by optional filters.",
			Parameters:  map[string]any{"type": "object", "properties": map[string]any{"query": map[string]any{"type": "string"}, "limit": map[string]any{"type": "integer"}}},
		}}},
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = EstimateRequestTokens(req)
	}
}
