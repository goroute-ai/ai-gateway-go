package catalog

import (
	"regexp"
	"strings"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
)

// InferredCapabilities holds heuristic capability and context-window defaults
// matched by model-family naming patterns. Values are explicitly marked Inferred
// and must not be treated as verified pricing or guaranteed provider callability.
type InferredCapabilities struct {
	Inferred        bool
	Source          string
	MaxInputTokens  int
	MaxOutputTokens int
	Capabilities    domain.ModelCapabilities
}

type familyRule struct {
	pattern *regexp.Regexp
	in      int
	out     int
	caps    domain.ModelCapabilities
}

var familyRules = []familyRule{
	{
		pattern: regexp.MustCompile(`(?i)^(?:us\.|eu\.|apac\.|global\.)?(?:anthropic\.)?claude-(?:opus-4-[67]|sonnet-4-[67]|4-[67]|5)`),
		in:      200000,
		out:     32000,
		caps: domain.ModelCapabilities{
			Tools:             domain.CapabilitySupported,
			Streaming:         domain.CapabilitySupported,
			Vision:            domain.CapabilitySupported,
			Reasoning:         domain.CapabilitySupported,
			StructuredOutputs: domain.CapabilitySupported,
		},
	},
	{
		pattern: regexp.MustCompile(`(?i)^(?:us\.|eu\.|apac\.|global\.)?(?:anthropic\.)?claude-(?:3-[57]|4|sonnet-4|opus-4|haiku-4)`),
		in:      200000,
		out:     8192,
		caps: domain.ModelCapabilities{
			Tools:     domain.CapabilitySupported,
			Streaming: domain.CapabilitySupported,
			Vision:    domain.CapabilitySupported,
		},
	},
	{
		pattern: regexp.MustCompile(`(?i)^(?:o[134](?:-mini|-pro|-preview)?|gpt-5)`),
		in:      200000,
		out:     32768,
		caps: domain.ModelCapabilities{
			Tools:             domain.CapabilitySupported,
			Streaming:         domain.CapabilitySupported,
			Vision:            domain.CapabilitySupported,
			Reasoning:         domain.CapabilitySupported,
			StructuredOutputs: domain.CapabilitySupported,
		},
	},
	{
		pattern: regexp.MustCompile(`(?i)^gpt-4`),
		in:      128000,
		out:     16384,
		caps: domain.ModelCapabilities{
			Tools:             domain.CapabilitySupported,
			Streaming:         domain.CapabilitySupported,
			Vision:            domain.CapabilitySupported,
			StructuredOutputs: domain.CapabilitySupported,
		},
	},
	{
		pattern: regexp.MustCompile(`(?i)^gemini-(?:2\.5|3)`),
		in:      1048576,
		out:     65536,
		caps: domain.ModelCapabilities{
			Tools:             domain.CapabilitySupported,
			Streaming:         domain.CapabilitySupported,
			Vision:            domain.CapabilitySupported,
			Reasoning:         domain.CapabilitySupported,
			StructuredOutputs: domain.CapabilitySupported,
		},
	},
	{
		pattern: regexp.MustCompile(`(?i)^gemini-`),
		in:      1048576,
		out:     8192,
		caps: domain.ModelCapabilities{
			Tools:             domain.CapabilitySupported,
			Streaming:         domain.CapabilitySupported,
			Vision:            domain.CapabilitySupported,
			StructuredOutputs: domain.CapabilitySupported,
		},
	},
	{
		pattern: regexp.MustCompile(`(?i)deepseek-(?:r1|reasoner)`),
		in:      64000,
		out:     8192,
		caps: domain.ModelCapabilities{
			Streaming: domain.CapabilitySupported,
			Reasoning: domain.CapabilitySupported,
		},
	},
}

// StripRegionalModelPrefix removes cloud-provider region prefixes (e.g. "us.", "eu.", "apac.", "global.")
// and trailing Bedrock version suffixes (e.g. ":0") for catalog lookup matching.
func StripRegionalModelPrefix(modelName string) string {
	clean := strings.TrimSpace(modelName)
	for _, pfx := range []string{"us.", "eu.", "apac.", "global."} {
		if len(clean) > len(pfx) && strings.EqualFold(clean[:len(pfx)], pfx) {
			clean = clean[len(pfx):]
			break
		}
	}
	if strings.HasSuffix(clean, ":0") && strings.Contains(clean, ".") {
		clean = strings.TrimSuffix(clean, ":0")
	}
	return clean
}

// InferFamilyCapabilities returns explicitly inferred capability defaults when a model
// is not yet in the catalog or has unknown capability fields.
func InferFamilyCapabilities(modelName string) InferredCapabilities {
	clean := StripRegionalModelPrefix(modelName)
	for _, r := range familyRules {
		if r.pattern.MatchString(clean) {
			return InferredCapabilities{
				Inferred:        true,
				Source:          "family-pattern-heuristic",
				MaxInputTokens:  r.in,
				MaxOutputTokens: r.out,
				Capabilities:    r.caps,
			}
		}
	}
	return InferredCapabilities{}
}

// BackfillCapabilities fills only CapabilityUnknown fields on caps from inferred family rules.
func BackfillCapabilities(caps domain.ModelCapabilities, modelName string) (domain.ModelCapabilities, bool) {
	inf := InferFamilyCapabilities(modelName)
	if !inf.Inferred {
		return caps, false
	}
	changed := false
	fill := func(dst *domain.CapabilityState, src domain.CapabilityState) {
		if (*dst == "" || *dst == domain.CapabilityUnknown) && src != "" && src != domain.CapabilityUnknown {
			*dst = src
			changed = true
		}
	}
	fill(&caps.Tools, inf.Capabilities.Tools)
	fill(&caps.Streaming, inf.Capabilities.Streaming)
	fill(&caps.Vision, inf.Capabilities.Vision)
	fill(&caps.Reasoning, inf.Capabilities.Reasoning)
	fill(&caps.StructuredOutputs, inf.Capabilities.StructuredOutputs)
	return caps, changed
}
