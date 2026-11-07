package main

import (
	"context"
	"log/slog"

	"github.com/goroute-ai/ai-gateway-go/demo/demoutil"
	"github.com/goroute-ai/ai-gateway-go/pkg/gateway"
)

func main() {
	ctx := context.Background()

	// Multi-Tenant Model Hierarchy & Dynamic Wildcard Routing
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

	demoutil.Banner("Model Management & Dynamic Wildcard Routing")

	// 1. List all models visible to this tenant across the 4-layer hierarchy
	//    (Layer 1 Catalogue ∩ Layer 2 Org Subscription ∩ Layer 3 Policy ∩ Layer 4 Key Scope)
	models, err := gw.ListModels(ctx)
	if err != nil {
		demoutil.Fail("Listing models failed", err)
	}
	demoutil.Section(1, "4-Layer Tenant-Filtered Model Inventory")
	demoutil.Field("Visible Models", len(models))
	for _, m := range models {
		demoutil.Item(m)
	}

	// 2. Dynamic "provider/model" routing without pre-creating an explicit alias
	demoutil.Section(2, "Dynamic Wildcard Routing ('gemini/gemini-2.5-flash')")
	res, err := gw.Chat(ctx, "gemini/gemini-2.5-flash", "Confirm dynamic provider/model resolution.")
	if err != nil {
		demoutil.Fail("Dynamic wildcard chat failed", err, slog.String("target", "gemini/gemini-2.5-flash"))
	}
	demoutil.Field("Status", "200 OK")
	demoutil.Field("Requested", "gemini/gemini-2.5-flash")
	demoutil.Fieldf("Resolved", "Provider=%s | Model=%s", res.Provider, res.Model)
	demoutil.Field("Response", res.Content)
}
