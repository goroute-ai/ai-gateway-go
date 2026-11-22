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
		{"us.claude-haiku-4-5-20251001", "claude-haiku-4-5-20251001"},
		{"eu.gpt-4o-mini", "gpt-4o-mini"},
		{"global.openai/gpt-oss-20b", "openai/gpt-oss-20b"},
		{"gpt-4o", "gpt-4o"},
	}
	for _, tc := range tests {
		if got := StripRegionalModelPrefix(tc.in); got != tc.want {
			t.Errorf("StripRegionalModelPrefix(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestInferFamilyCapabilities_ExplicitlyInferred(t *testing.T) {
	inf := InferFamilyCapabilities("claude-sonnet-4-6-20260101")
	if !inf.Inferred || inf.Source != "family-pattern-heuristic" {
		t.Fatalf("expected explicit inferred result, got %+v", inf)
	}
	if inf.Capabilities.Reasoning != domain.CapabilitySupported || inf.Capabilities.Vision != domain.CapabilitySupported {
		t.Errorf("expected reasoning and vision supported, got %+v", inf.Capabilities)
	}

	gpt6 := InferFamilyCapabilities("gpt-6-astra")
	if !gpt6.Inferred || gpt6.Capabilities.Reasoning != domain.CapabilitySupported {
		t.Errorf("expected gpt-6-astra reasoning inferred, got %+v", gpt6)
	}

	oss := InferFamilyCapabilities("openai/gpt-oss-20b")
	if !oss.Inferred || oss.Capabilities.Tools != domain.CapabilitySupported || oss.Capabilities.Reasoning != domain.CapabilitySupported {
		t.Errorf("expected openai/gpt-oss-20b inferred tools+reasoning, got %+v", oss)
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
