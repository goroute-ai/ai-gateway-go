package main

import (
	"context"
	"log/slog"

	"github.com/goroute-ai/ai-gateway-go/demo/demoutil"
	"github.com/goroute-ai/ai-gateway-go/pkg/gateway"
)

func main() {
	ctx := context.Background()

	// Unified OpenAI-Compatible API & Wire Normalization across 5 Upstream Protocols
	gw, err := gateway.New(
		gateway.WithModelList(
			gateway.ModelEntry{
				ModelName: "fast",
				Model:     "gemini/gemini-2.5-flash",
				APIKey:    "os.environ/GEMINI_API_KEY",
			},
		),
		gateway.WithDemoMocksIfEnvMissing(),
	)
	if err != nil {
		demoutil.Fail("Gateway initialization failed", err)
	}
	defer gw.Close()

	demoutil.Banner("Unified API & Real-Time SSE Token Streaming")

	// 1. Synchronous Chat Completion with System Prompt & MaxTokens
	demoutil.Part(1, "Synchronous Chat Completion")
	res, err := gw.Chat(ctx, "fast", "Explain why Pure Go is ideal for high-throughput network proxies.",
		gateway.WithSystem("Answer in one concise sentence."),
		gateway.WithMaxTokens(128),
	)
	if err != nil {
		demoutil.Fail("Chat completion failed", err, slog.String("part", "sync"))
	}
	demoutil.Field("Status", "200 OK")
	demoutil.Field("Provider", res.Provider)
	demoutil.Field("Model", res.Model)
	demoutil.Fieldf("Tokens", "Prompt=%d, Completion=%d, Total=%d", res.Usage.PromptTokens, res.Usage.CompletionTokens, res.Usage.TotalTokens)
	demoutil.Fieldf("Cost", "%d micro-USD (%d µ$)", res.CostMicros, res.CostMicros)
	demoutil.Field("Response", res.Content)

	// 2. Real-Time Zero-Buffer SSE Streaming (StreamChat)
	demoutil.Part(2, "Real-Time Zero-Buffer SSE Streaming")
	demoutil.StreamHeader("SSE Stream")
	streamRes, err := gw.StreamChat(ctx, "fast", "Stream a 1-sentence summary of GoRoute AI Gateway.", func(delta string) error {
		demoutil.StreamDelta(delta)
		return nil
	})
	if err != nil {
		demoutil.Fail("Streaming chat failed", err, slog.String("part", "streaming"))
	}
	demoutil.StreamDone(streamRes.RequestID, streamRes.Usage.TotalTokens)
}
