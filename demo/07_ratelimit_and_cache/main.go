package main

import (
	"context"
	"fmt"

	"github.com/goroute-ai/ai-gateway-go/demo/demoutil"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/pkg/gateway"
)

func main() {
	ctx := context.Background()

	// Deterministic Exact-Match Response Caching & Atomic Sliding-Window Rate Limiting
	gw, err := gateway.New(
		gateway.WithModelList(
			gateway.ModelEntry{ModelName: "fast", Model: "gemini/gemini-2.5-flash"},
		),
		gateway.WithDemoMocksIfEnvMissing(),
	)
	if err != nil {
		demoutil.Fail("Gateway initialization failed", err)
	}
	defer gw.Close()

	demoutil.Banner("Deterministic Cache & Atomic RPM Rate Limiting")

	// Part A: Deterministic Exact-Match Response Caching (Temperature = 0.0)
	demoutil.Part(1, "Deterministic Exact-Match Response Caching")
	first, err := gw.Chat(ctx, "fast", "What is 2 + 2?", gateway.WithTemperature(0.0))
	if err != nil {
		demoutil.Fail("Cache request 1 failed", err)
	}
	second, err := gw.Chat(ctx, "fast", "What is 2 + 2?", gateway.WithTemperature(0.0))
	if err != nil {
		demoutil.Fail("Cache request 2 failed", err)
	}

	demoutil.Fieldf("Call 1: Fresh", "Status=%-4s | Cost=%d µ$ (Evaluated upstream)", first.CacheStatus, first.CostMicros)
	demoutil.Fieldf("Call 2: Cached", "Status=%-4s | Cost=%d µ$ (0ms, $0.00 upstream bypass)", second.CacheStatus, second.CostMicros)

	// Part B: Atomic RPM Quota Enforcement (RPMLimit = 2 requests/minute)
	demoutil.Part(2, "Atomic RPM Quota Enforcement (RPMLimit = 2)")
	vk, err := gw.IssueVirtualKey(ctx, domain.VirtualKey{Name: "rpm-limited-key", RPMLimit: 2})
	if err != nil {
		demoutil.Fail("Failed to issue rate-limited key", err)
	}
	limitedClient := gw.WithKey(vk.RawKey)

	for i := 1; i <= 3; i++ {
		_, err := limitedClient.Chat(ctx, "fast", fmt.Sprintf("Non-cached request #%d", i))
		label := fmt.Sprintf("Request %d/3", i)
		if err != nil {
			demoutil.Fieldf(label, "BLOCKED  -> %v", err)
		} else {
			demoutil.Fieldf(label, "ALLOWED  -> 200 OK (Quota used: %d/2)", i)
		}
	}
}
