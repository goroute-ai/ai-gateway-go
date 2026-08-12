// Package openapi contains build-time go:generate directives that validate the
// repository OpenAPI specifications in docs/openapi/ (gateway.openapi.yaml,
// openai.openapi.yaml, anthropic.openapi.yaml, gemini.openapi.yaml,
// mistral.openapi.yaml, and ollama.openapi.yaml) and provide strongly-typed Go DTOs.
package openapi

//go:generate go run ../../cmd/specgen/main.go -root ../..
