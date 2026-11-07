package main

import (
	"context"
	"log/slog"

	"github.com/goroute-ai/ai-gateway-go/demo/demoutil"
	"github.com/goroute-ai/ai-gateway-go/pkg/gateway"
)

func main() {
	ctx := context.Background()

	// 1. Initialize the Gateway Router declaratively with model entries and aliases.
	//    Supports explicit provider models, weights, strategies, and fallback chains.
	gw, err := gateway.New(
		gateway.WithModelList(
			gateway.ModelEntry{
				ModelName: "fast",
				Model:     "gemini/gemini-2.5-flash",
				APIKey:    "os.environ/GEMINI_API_KEY",
			},
			gateway.ModelEntry{
				ModelName: "reasoning",
				Model:     "anthropic/claude-sonnet-4-20250514",
				APIKey:    "os.environ/ANTHROPIC_API_KEY",
			},
		),
		gateway.WithDemoMocksIfEnvMissing(),
	)
	if err != nil {
		demoutil.Fail("Gateway initialization failed", err)
	}
	defer gw.Close()

	demoutil.Banner("GoRoute AI Gateway — Overview Laboratory Demo")

	// Mode 1: Explicit Model Name ("gemini-2.5-flash")
	res1, err := gw.Chat(ctx, "gemini-2.5-flash", "Explain Pure Go in one sentence.")
	if err != nil {
		demoutil.Fail("Chat request failed", err, slog.String("mode", "explicit"))
	}
	printResult(`Mode 1: Explicit Model Name ("gemini-2.5-flash")`, res1)

	// Mode 2: Logical Alias ("fast")
	res2, err := gw.Chat(ctx, "fast", "What is 2 + 2?")
	if err != nil {
		demoutil.Fail("Chat request failed", err, slog.String("mode", "alias"))
	}
	printResult(`Mode 2: Logical Alias ("fast")`, res2)

	// Mode 3: Smart Zero-LLM Complexity Classifier ("auto")
	res3, err := gw.Chat(ctx, "auto", "Analyze and architect a distributed consensus protocol step by step: prove safety guarantees and debug this code:\n```go\nfunc electLeader() { select {} }\n```")
	if err != nil {
		demoutil.Fail("Chat request failed", err, slog.String("mode", "auto"))
	}
	printResult(`Mode 3: Smart Zero-LLM Auto-Router ("auto")`, res3)

	// Subsystem Demonstration Index
	demoutil.Banner("Explore Specialized Subsystem Demos in ./demo/")
	demoutil.Field("01. Unified API", "go run ./demo/01_unified_api (Chat, SSE Streaming & Adapters)")
	demoutil.Field("02. Models & Groups", "go run ./demo/02_model_management (Declarative Catalogue)")
	demoutil.Field("03. Smart Routing", "go run ./demo/03_smart_routing (Heuristic Classifier & Balancer)")
	demoutil.Field("04. Auth & RBAC", "go run ./demo/04_auth_and_vault (Virtual Keys & AES-256 Vault)")
	demoutil.Field("05. Reliability", "go run ./demo/05_retries_and_fallbacks (Circuit Breakers & Retries)")
	demoutil.Field("06. FinOps", "go run ./demo/06_finops_and_budgets (Micro-Dollar Spend Ledger)")
	demoutil.Field("07. Cache & Limits", "go run ./demo/07_ratelimit_and_cache (Exact-Match Cache & RPM)")
	demoutil.Field("08. MCP Gateway", "go run ./demo/08_mcp_gateway (MCP 2026-07-28 Hub & Tool Pinning)")
	demoutil.Field("09. A2A Protocol", "go run ./demo/09_a2a_protocol (A2A v1.0 JCS Signing & SSE Streams)")
}

func printResult(title string, r *gateway.ChatResult) {
	demoutil.Header(title)
	demoutil.Field("Provider", r.Provider)
	demoutil.Field("Model", r.Model)
	demoutil.Fieldf("Cost", "%d µ$", r.CostMicros)
	demoutil.Fieldf("Route Time", "%d µs", r.RoutingMicros)
	if r.RouteReason != "" {
		demoutil.Field("Decision", r.RouteReason)
	}
	demoutil.Field("Response", r.Content)
}
