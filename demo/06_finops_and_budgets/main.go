package main

import (
	"context"

	"github.com/goroute-ai/ai-gateway-go/demo/demoutil"
	"github.com/goroute-ai/ai-gateway-go/pkg/gateway"
)

func main() {
	ctx := context.Background()

	// FinOps Token Accounting, Micro-Dollar Cost Calculation & Real-Time Spend Ledgers
	gw, err := gateway.New(
		gateway.WithModelList(
			gateway.ModelEntry{ModelName: "fast", Model: "gemini/gemini-2.5-flash"},
			gateway.ModelEntry{ModelName: "reasoning", Model: "anthropic/claude-sonnet-4-20250514"},
		),
		gateway.WithDemoMocksIfEnvMissing(),
	)
	if err != nil {
		demoutil.Fail("Gateway initialization failed", err)
	}
	defer gw.Close()

	demoutil.Banner("Micro-Dollar Accounting & Aggregated Spend Ledgers")

	// Call 1: Fast Tier Model
	r1, err := gw.Chat(ctx, "fast", "Calculate fast tier token cost.")
	if err != nil {
		demoutil.Fail("Fast tier call failed", err)
	}
	demoutil.Header("Call 1: Fast Tier — " + r1.Model)
	demoutil.Fieldf("Tokens", "Total=%d (Prompt=%d, Completion=%d)", r1.Usage.TotalTokens, r1.Usage.PromptTokens, r1.Usage.CompletionTokens)
	demoutil.Fieldf("Cost", "%d micro-USD (%d µ$)  |  USD: $%.6f", r1.CostMicros, r1.CostMicros, float64(r1.CostMicros)/1_000_000.0)

	// Call 2: Reasoning Tier Model
	r2, err := gw.Chat(ctx, "reasoning", "Calculate reasoning tier token cost.")
	if err != nil {
		demoutil.Fail("Reasoning tier call failed", err)
	}
	demoutil.Header("Call 2: Reasoning Tier — " + r2.Model)
	demoutil.Fieldf("Tokens", "Total=%d (Prompt=%d, Completion=%d)", r2.Usage.TotalTokens, r2.Usage.PromptTokens, r2.Usage.CompletionTokens)
	demoutil.Fieldf("Cost", "%d micro-USD (%d µ$)  |  USD: $%.6f", r2.CostMicros, r2.CostMicros, float64(r2.CostMicros)/1_000_000.0)

	// Aggregate FinOps Spend Summary across all tenant activity
	demoutil.Header("Aggregated Real-Time Spend Summary")
	summary, err := gw.SpendSummary(ctx)
	if err != nil {
		demoutil.Fail("Spend summary query failed", err)
	}
	demoutil.Fieldf("Total Calls", "%d requests", summary.TotalRequests)
	demoutil.Fieldf("Total Tokens", "%d tokens", summary.TotalTokens)
	demoutil.Fieldf("Total Spend", "%d micro-USD ($%.6f)", summary.TotalCostMicros, summary.TotalCostUSD)
	demoutil.Field("Spend by Provider", summary.SpendByProvider)
	demoutil.Field("Spend by Model", summary.SpendByModel)
}
