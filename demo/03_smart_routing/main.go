package main

import (
	"context"

	"github.com/goroute-ai/ai-gateway-go/demo/demoutil"
	"github.com/goroute-ai/ai-gateway-go/pkg/gateway"
)

func main() {
	ctx := context.Background()

	// Two-Stage Intelligent Routing & Advanced Load Balancing
	gw, err := gateway.New(
		gateway.WithModelList(
			// Two load-balanced deployments under the "fast" alias with weighted traffic splitting
			gateway.ModelEntry{
				ModelName:       "fast",
				Model:           "gemini/gemini-2.5-flash",
				RoutingStrategy: "weighted-shuffle",
				Weight:          80,
			},
			gateway.ModelEntry{
				ModelName:       "fast",
				Model:           "openai/gpt-4.1-mini",
				RoutingStrategy: "weighted-shuffle",
				Weight:          20,
			},
			// Deep reasoning model group used by "auto" when prompt complexity >= 0.40
			gateway.ModelEntry{
				ModelName: "reasoning",
				Model:     "anthropic/claude-sonnet-4-20250514",
			},
		),
		gateway.WithDemoMocksIfEnvMissing(),
	)
	if err != nil {
		demoutil.Fail("Gateway initialization failed", err)
	}
	defer gw.Close()

	demoutil.Banner("Intelligent Routing & Advanced Load Balancing Strategies")

	// Mode 1: Explicit Model Name
	demoutil.Mode(1, "Explicit Target")
	r1, err := gw.Chat(ctx, "gemini-2.5-flash", "Hello from Mode 1")
	if err != nil {
		demoutil.Fail("Chat request failed", err)
	}
	demoutil.Field("Target", "gemini-2.5-flash")
	demoutil.Fieldf("Resolved", "Provider=%s | Model=%s", r1.Provider, r1.Model)
	demoutil.Fieldf("Overhead", "%d µs", r1.RoutingMicros)

	// Mode 2: Load-Balanced Logical Alias ("fast" - 80% Gemini / 20% OpenAI)
	demoutil.Mode(2, "Load-Balanced Alias ('fast')")
	r2, err := gw.Chat(ctx, "fast", "Hello from Mode 2 load-balanced alias")
	if err != nil {
		demoutil.Fail("Chat request failed", err)
	}
	demoutil.Field("Alias", "fast (Strategy: weighted-shuffle)")
	demoutil.Fieldf("Resolved", "Provider=%s | Model=%s", r2.Provider, r2.Model)
	demoutil.Field("Decision", r2.RouteReason)

	// Mode 3: Smart Zero-LLM Complexity Classifier ("auto")
	demoutil.Mode(3, "Zero-LLM Heuristic Complexity Classifier ('auto')")
	prompt := "Analyze and prove Raft consensus election safety step by step:\n```go\nfunc vote(term int) bool { return term > 0 }\n```"
	demoutil.Field("Input Prompt", prompt)
	r3, err := gw.Chat(ctx, "auto", prompt)
	if err != nil {
		demoutil.Fail("Chat request failed", err)
	}
	demoutil.Fieldf("Resolved", "Provider=%s | Model=%s", r3.Provider, r3.Model)
	demoutil.Field("Decision", r3.RouteReason)
	demoutil.Fieldf("Route Time", "%d µs (< 0.1ms)", r3.RoutingMicros)
}
