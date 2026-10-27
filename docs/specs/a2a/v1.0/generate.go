// Package a2aspec hosts official A2A v1.0 protocol buffer definitions and code generation directives.
package a2aspec

//go:generate protoc --experimental_allow_proto3_optional -I=. -I=../../third_party --go_out=../../../.. --go_opt=module=github.com/goroute-ai/ai-gateway-go a2a.proto
