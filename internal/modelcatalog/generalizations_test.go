package catalog

import (
	"testing"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
)

func TestStripRegionalModelPrefix(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"us.anthropic.claude-3-7-sonnet-20250219-v1:0", "anthropic.claude-3-7-sonnet-20250219-v1"},
		{"eu.anthropic.claude-sonnet-4-20250514-v1:0", "anthropic.claude-sonnet-4-20250514-v1"},
		{"global.anthropic.claude-opus-4-6-v1", "anthropic.claude-opus-4-6-v1"},
		{"gpt-4o", "gpt-4o"},
	}
	for _, tc := range tests {
		if got := StripRegionalModelPrefix(tc.in); got != tc.want {
			t.Errorf("StripRegionalModelPrefix(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestInferFamilyCapabilities_ExplicitlyInferred(t *testing.T) {
	inf := InferFamilyCapabilities("us.anthropic.claude-sonnet-4-6-20260101-v1:0")
	if !inf.Inferred || inf.Source != "family-pattern-heuristic" {
		t.Fatalf("expected explicit inferred result, got %+v", inf)
	}
	if inf.Capabilities.Reasoning != domain.CapabilitySupported || inf.Capabilities.Vision != domain.CapabilitySupported {
		t.Errorf("expected reasoning and vision supported, got %+v", inf.Capabilities)
	}

	unknown := InferFamilyCapabilities("completely-custom-local-model")
	if unknown.Inferred {
		t.Errorf("expected Inferred=false for unknown model, got %+v", unknown)
	}
}

func TestBackfillCapabilities_OnlyFillsUnknown(t *testing.T) {
	caps := domain.ModelCapabilities{
		Tools:  domain.CapabilityUnsupported,
		Vision: domain.CapabilityUnknown,
	}
	out, changed := BackfillCapabilities(caps, "gpt-5-preview")
	if !changed {
		t.Fatalf("expected BackfillCapabilities to report changed=true")
	}
	if out.Tools != domain.CapabilityUnsupported {
		t.Errorf("expected existing CapabilityUnsupported to be preserved, got %q", out.Tools)
	}
	if out.Vision != domain.CapabilitySupported || out.Reasoning != domain.CapabilitySupported {
		t.Errorf("expected Vision and Reasoning backfilled, got %+v", out)
	}
}
