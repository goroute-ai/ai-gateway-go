// Package a2aspec embeds the authoritative A2A v1.0 OpenAPI 3.1.0 specification and
// holds generated models, Chi server interfaces, and strict runtime schema validators.
package a2aspec

//go:generate cp ../../../docs/openapi/a2a.openapi.yaml a2a.openapi.yaml
//go:generate go run github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@v2.8.0 -config ../../../docs/openapi/a2a.codegen.yaml a2a.openapi.yaml
