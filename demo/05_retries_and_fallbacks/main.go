package main

import (
	"context"

	"github.com/goroute-ai/ai-gateway-go/demo/demoutil"
	"github.com/goroute-ai/ai-gateway-go/pkg/gateway"
)

func main() {
	ctx := context.Background()

	// Automated Retries, 3-State Circuit Breakers & Cross-Provider Fallbacks
	gw, err := gateway.New(
		gateway.WithModelList(
			// Primary model group simulates an upstream HTTP 503 outage and falls back to "backup-claude"
			gateway.ModelEntry{
				ModelName:      "production-chat",
				Model:          "gemini/gemini-2.5-flash",
				Fallbacks:      []string{"backup-claude"},
				SimulateStatus: 503,
			},
			// Secondary cross-provider fallback group (Anthropic Claude Sonnet 4)
			gateway.ModelEntry{
				ModelName: "backup-claude",
				Model:     "anthropic/claude-sonnet-4-20250514",
			},
		),
		gateway.WithDemoMocksIfEnvMissing(),
	)
	if err != nil {
		demoutil.Fail("Gateway initialization failed", err)
	}
	defer gw.Close()

	demoutil.Banner("Circuit Breakers, Retries & Cross-Provider Failover")

	demoutil.Header("Scenario Configuration")
	demoutil.Field("Primary", "production-chat (gemini/gemini-2.5-flash -> Simulated HTTP 503 Outage)")
	demoutil.Field("Fallback", "backup-claude (anthropic/claude-sonnet-4-20250514)")

	demoutil.LogWarn("simulated_outage_triggered", "status", 503, "target", "production-chat")

	res, err := gw.Chat(ctx, "production-chat", "Summarize high-availability failover in one sentence.")
	if err != nil {
		demoutil.Fail("Inference call failed after fallback", err)
	}

	demoutil.Header("Recovery Result")
	demoutil.Field("Fallback Used", res.FallbackAttempted)
	demoutil.Fieldf("Winning Target", "Provider=%-12s | Model=%s", res.Provider, res.Model)
	demoutil.Fieldf("Cost", "%d µ$", res.CostMicros)
	demoutil.Field("Response", res.Content)
}
