// Package gateway provides an embeddable, production-ready Go client and in-process
// router engine for the GoRoute AI Gateway.
//
// The package supports both in-process embedded routing (running within your Go service
// without an external HTTP daemon) and remote HTTP client modes communicating with a
// standalone GoRoute proxy container.
//
// Key Features:
//   - Unified OpenAI-compatible interface across Google Gemini, Anthropic Claude, OpenAI, Mistral, and Ollama.
//   - In-process or remote Chat completion and zero-buffer Server-Sent Events (SSE) token streaming.
//   - Declarative model aliasing (e.g. "fast", "reasoning", "auto") with automated heuristic complexity classification.
//   - Enterprise resilience: automatic retries, cross-provider fallbacks, and 3-state circuit breakers.
//   - Model Context Protocol (MCP 2026-07-28 & 2025-11-25) tool invocation, schema validation, and toolset execution.
//   - Linux Foundation Agent-to-Agent (A2A v1.0) task dispatch, timeline streaming, and emergency kill-switch controls.
//
// Basic In-Process Embedded Example:
//
//	package main
//
//	import (
//		"context"
//		"fmt"
//		"log"
//
//		"github.com/goroute-ai/ai-gateway-go/pkg/gateway"
//	)
//
//	func main() {
//		ctx := context.Background()
//
//		gw, err := gateway.New(
//			gateway.WithModelList(
//				gateway.ModelEntry{ModelName: "fast", Model: "gemini/gemini-2.5-flash", APIKey: "os.environ/GEMINI_API_KEY"},
//				gateway.ModelEntry{ModelName: "reasoning", Model: "anthropic/claude-sonnet-4-20250514", APIKey: "os.environ/ANTHROPIC_API_KEY"},
//			),
//			gateway.WithDemoMocksIfEnvMissing(),
//		)
//		if err != nil {
//			log.Fatal(err)
//		}
//		defer gw.Close()
//
//		res, err := gw.Chat(ctx, "fast", "Explain Pure Go in one sentence.")
//		if err != nil {
//			log.Fatal(err)
//		}
//		fmt.Printf("[%s] %s\n", res.Provider, res.Content)
//	}
//
// Remote HTTP Proxy Client Example:
//
//	client := gateway.NewClient("http://localhost:8080", "sk-gw-my-virtual-key")
//	res, err := client.Chat(ctx, "fast", "Hello via remote proxy!")
package gateway
