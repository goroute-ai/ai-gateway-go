// Package gemini implements the OpenAPI-spec-first ProviderAdapter for the
// Google Gemini Generative Language API (v1beta).
//
// It translates GoRoute canonical chat, streaming, embeddings, and model
// discovery requests to Google's native v1beta wire protocol using DTOs
// generated from docs/openapi/gemini.openapi.yaml, enforcing SSRF base URL
// policies, strict header-based API key authentication (x-goog-api-key),
// bounded response reads, W3C traceparent propagation, and exact thinking-token
// usage accounting.
package gemini
