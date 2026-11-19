package catalog

import (
	"bytes"
	"compress/gzip"
	_ "embed"
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
)

//go:embed catalog.json.gz
var defaultCatalogGz []byte

// QualityTier constants categorize model capability and cost tiers for pre-routing.
const (
	QualityTierUnknown   = 0
	QualityTierEconomy   = 1
	QualityTierStandard  = 2
	QualityTierFrontier  = 3
	QualityTierReasoning = 4
)

var (
	once         sync.Once
	modelsByID   map[string]*domain.GlobalModel
	modelsByPN   map[string]*domain.GlobalModel
	modelsByName map[string]*domain.GlobalModel
	catalogList  []*domain.GlobalModel
)

func initCatalog() {
	modelsByID = make(map[string]*domain.GlobalModel)
	modelsByPN = make(map[string]*domain.GlobalModel)
	modelsByName = make(map[string]*domain.GlobalModel)

	if len(defaultCatalogGz) == 0 {
		return
	}

	gr, err := gzip.NewReader(bytes.NewReader(defaultCatalogGz))
	if err != nil {
		return
	}
	defer gr.Close()

	var rawMap map[string]*domain.GlobalModel
	if err := json.NewDecoder(gr).Decode(&rawMap); err != nil {
		return
	}

	catalogList = make([]*domain.GlobalModel, 0, len(rawMap))
	for id, m := range rawMap {
		if m == nil {
			continue
		}
		if m.QualityTier == 0 {
			m.QualityTier = inferQualityTier(m)
		}
		modelsByID[id] = m
		modelsByID[strings.ToLower(id)] = m
		pnKey := fmt.Sprintf("%s/%s", strings.ToLower(string(m.Provider)), strings.ToLower(m.ModelName))
		modelsByPN[pnKey] = m

		nameKey := strings.ToLower(m.ModelName)
		if _, exists := modelsByName[nameKey]; !exists {
			modelsByName[nameKey] = m
		} else {
			// Prefer primary/authoritative provider for bare model names
			if (strings.HasPrefix(nameKey, "gpt-") || strings.HasPrefix(nameKey, "o1-") || strings.HasPrefix(nameKey, "o3-") || strings.HasPrefix(nameKey, "text-embedding-")) && m.Provider == domain.ProviderOpenAI {
				modelsByName[nameKey] = m
			} else if strings.HasPrefix(nameKey, "claude-") && m.Provider == domain.ProviderAnthropic {
				modelsByName[nameKey] = m
			} else if strings.HasPrefix(nameKey, "gemini-") && (m.Provider == domain.ProviderGemini || m.Provider == domain.ProviderVertex) {
				modelsByName[nameKey] = m
			} else if strings.HasPrefix(nameKey, "deepseek-") && m.Provider == domain.ProviderDeepSeek {
				modelsByName[nameKey] = m
			}
		}

		catalogList = append(catalogList, m)
	}
}

// EnsureLoaded ensures the embedded catalogue is loaded into memory.
func EnsureLoaded() {
	once.Do(initCatalog)
}

// Count returns the total number of unique models in the catalogue.
func Count() int {
	EnsureLoaded()
	return len(catalogList)
}

// IsCallableProvider returns true if GoRoute has a supported transport
// (either a dedicated adapter or a certified OpenAI-compatible profile)
// for the given provider.
func IsCallableProvider(prov domain.ProviderType) bool {
	norm := config.NormalizeProvider(string(prov))
	for _, p := range domain.AllProviders() {
		if norm == p {
			return true
		}
	}
	return false
}

// All returns all models in the curated catalogue.
func All() []*domain.GlobalModel {
	EnsureLoaded()
	out := make([]*domain.GlobalModel, len(catalogList))
	copy(out, catalogList)
	return out
}

// Lookup finds a model by its canonical GlobalModelID (e.g. "groq/llama-3.3-70b-versatile"),
// an aliased ID (e.g. "vertex_ai/gemini-1.5-pro"), or bare model name.
func Lookup(globalModelID string) (*domain.GlobalModel, bool) {
	EnsureLoaded()
	clean := strings.TrimSpace(globalModelID)
	if clean == "" {
		return nil, false
	}
	if m, ok := modelsByID[clean]; ok {
		cp := *m
		if cp.QualityTier == 0 {
			cp.QualityTier = inferQualityTier(&cp)
		}
		return &cp, true
	}
	lower := strings.ToLower(clean)
	if m, ok := modelsByID[lower]; ok {
		cp := *m
		if cp.QualityTier == 0 {
			cp.QualityTier = inferQualityTier(&cp)
		}
		return &cp, true
	}
	if idx := strings.IndexByte(clean, '/'); idx > 0 {
		normProv := config.NormalizeProvider(clean[:idx])
		bareModel := clean[idx+1:]
		pnKey := fmt.Sprintf("%s/%s", strings.ToLower(string(normProv)), strings.ToLower(bareModel))
		if m, ok := modelsByPN[pnKey]; ok {
			cp := *m
			if cp.QualityTier == 0 {
				cp.QualityTier = inferQualityTier(&cp)
			}
			return &cp, true
		}
	} else {
		if m, ok := modelsByName[lower]; ok {
			cp := *m
			if cp.QualityTier == 0 {
				cp.QualityTier = inferQualityTier(&cp)
			}
			return &cp, true
		}
	}
	return nil, false
}

// LookupByProviderAndModel finds a model by its provider and model name,
// automatically normalizing provider aliases (e.g. "vertex_ai" -> "vertex", "bedrock_converse" -> "bedrock")
// and stripping regional prefixes (e.g. "us.", "eu.", "apac.", "global.") on fallback.
func LookupByProviderAndModel(prov domain.ProviderType, modelName string) (*domain.GlobalModel, bool) {
	EnsureLoaded()
	normProv := config.NormalizeProvider(string(prov))
	cleanModel := strings.TrimSpace(modelName)
	pnKey := fmt.Sprintf("%s/%s", strings.ToLower(string(normProv)), strings.ToLower(cleanModel))
	if m, ok := modelsByPN[pnKey]; ok {
		cp := *m
		backfillInferredModelFields(&cp, cleanModel)
		return &cp, true
	}
	if stripped := StripRegionalModelPrefix(cleanModel); stripped != cleanModel {
		pnStripped := fmt.Sprintf("%s/%s", strings.ToLower(string(normProv)), strings.ToLower(stripped))
		if m, ok := modelsByPN[pnStripped]; ok {
			cp := *m
			backfillInferredModelFields(&cp, cleanModel)
			return &cp, true
		}
	}
	// Try direct lookup with normalized provider
	if m, ok := Lookup(fmt.Sprintf("%s/%s", normProv, cleanModel)); ok {
		backfillInferredModelFields(m, cleanModel)
		return m, true
	}
	return ApplyGeneralizations(normProv, cleanModel)
}

// ApplyGeneralizations synthesizes conservative model metadata for a recognized
// family when its exact model ID is absent from the embedded catalog. It never
// infers pricing; unknown pricing remains fail-closed for budgeted requests.
func ApplyGeneralizations(prov domain.ProviderType, modelName string) (*domain.GlobalModel, bool) {
	normProv := config.NormalizeProvider(string(prov))
	cleanName := strings.TrimSpace(modelName)
	inf := InferFamilyCapabilities(cleanName)
	if normProv == "" || cleanName == "" || !inf.Inferred || !IsCallableProvider(normProv) {
		return nil, false
	}
	if stripped := StripRegionalModelPrefix(cleanName); stripped != "" {
		cleanName = stripped
	}
	gm := &domain.GlobalModel{
		ID:                fmt.Sprintf("%s/%s", normProv, cleanName),
		Provider:          normProv,
		ModelName:         cleanName,
		DisplayName:       cleanName,
		MaxInputTokens:    inf.MaxInputTokens,
		MaxOutputTokens:   inf.MaxOutputTokens,
		Capabilities:      inf.Capabilities,
		SupportsInference: true,
		SupportsStreaming: inf.Capabilities.Streaming == domain.CapabilitySupported,
		SupportsTools:     inf.Capabilities.Tools == domain.CapabilitySupported,
		SupportsVision:    inf.Capabilities.Vision == domain.CapabilitySupported,
		SupportsReasoning: inf.Capabilities.Reasoning == domain.CapabilitySupported,
		SupportedOperations: []domain.OperationType{
			domain.OperationChat,
		},
		PricingStatus:           domain.PricingStatusUnknown,
		PricingProvenanceSource: inf.Source,
		LifecycleStatus:         domain.ModelStatusActive,
	}
	gm.QualityTier = inferQualityTier(gm)
	return gm, true
}

func backfillInferredModelFields(model *domain.GlobalModel, modelName string) {
	if model == nil {
		return
	}
	model.Capabilities, _ = BackfillCapabilities(model.Capabilities, modelName)
	if inf := InferFamilyCapabilities(modelName); inf.Inferred {
		if model.MaxInputTokens <= 0 {
			model.MaxInputTokens = inf.MaxInputTokens
		}
		if model.MaxOutputTokens <= 0 {
			model.MaxOutputTokens = inf.MaxOutputTokens
		}
	}
	resolved := model.ResolveCapabilities()
	model.SupportsStreaming = resolved.Streaming == domain.CapabilitySupported
	model.SupportsTools = resolved.Tools == domain.CapabilitySupported
	model.SupportsVision = resolved.Vision == domain.CapabilitySupported
	model.SupportsReasoning = resolved.Reasoning == domain.CapabilitySupported
	if model.QualityTier == 0 {
		model.QualityTier = inferQualityTier(model)
	}
}

// InferQualityTier returns a model's explicit QualityTier when set, or infers
// one of 1=economy, 2=standard, 3=frontier, 4=reasoning from capabilities,
// model family name, and pricing.
func InferQualityTier(m *domain.GlobalModel) int {
	return inferQualityTier(m)
}

func inferQualityTier(m *domain.GlobalModel) int {
	if m == nil {
		return QualityTierUnknown
	}
	if m.QualityTier > 0 {
		return m.QualityTier
	}

	rawName := strings.TrimSpace(m.ModelName)
	if rawName == "" {
		rawName = strings.TrimSpace(m.ID)
	}
	if idx := strings.LastIndexByte(rawName, '/'); idx >= 0 && idx+1 < len(rawName) {
		rawName = rawName[idx+1:]
	}
	base := strings.ToLower(StripRegionalModelPrefix(rawName))

	// Dedicated reasoning families take precedence (including o3-mini / o4-mini).
	if hasModelPrefix(base, "o1", "o3", "o4") ||
		strings.Contains(base, "reasoner") ||
		strings.Contains(base, "-r1") ||
		strings.HasPrefix(base, "r1-") ||
		base == "r1" ||
		strings.Contains(base, "qwq") ||
		strings.Contains(base, "thinking") ||
		strings.Contains(base, "deep-research") {
		return QualityTierReasoning
	}

	isEconomyName := strings.Contains(base, "nano") ||
		strings.Contains(base, "mini") ||
		strings.Contains(base, "flash") ||
		strings.Contains(base, "lite") ||
		strings.Contains(base, "haiku") ||
		strings.Contains(base, "micro") ||
		strings.Contains(base, "tiny") ||
		strings.Contains(base, "instant") ||
		strings.Contains(base, "gpt-3.5") ||
		strings.Contains(base, "8b") ||
		strings.Contains(base, "7b") ||
		strings.Contains(base, "3b") ||
		strings.Contains(base, "1b") ||
		strings.Contains(base, "small")

	if (m.SupportsReasoning || m.Capabilities.Reasoning == domain.CapabilitySupported) && !isEconomyName {
		return QualityTierReasoning
	}

	if isEconomyName {
		if m.OutputCostMicrosPer1M > 2_000_000 || m.InputCostMicrosPer1M > 1_000_000 {
			return QualityTierStandard
		}
		return QualityTierEconomy
	}

	if m.InputCostMicrosPer1M >= 1_500_000 || m.OutputCostMicrosPer1M >= 6_000_000 {
		return QualityTierFrontier
	}

	if strings.Contains(base, "opus") ||
		strings.Contains(base, "sonnet") ||
		strings.Contains(base, "gpt-4o") ||
		strings.Contains(base, "gpt-4.1") ||
		strings.Contains(base, "gpt-4-turbo") ||
		strings.Contains(base, "gpt-5") ||
		strings.Contains(base, "ultra") ||
		strings.Contains(base, "large") ||
		strings.Contains(base, "405b") ||
		strings.Contains(base, "-pro") {
		return QualityTierFrontier
	}

	if (m.InputCostMicrosPer1M > 0 || m.OutputCostMicrosPer1M > 0) &&
		m.InputCostMicrosPer1M <= 500_000 && m.OutputCostMicrosPer1M <= 2_000_000 {
		return QualityTierEconomy
	}

	return QualityTierStandard
}

func hasModelPrefix(name string, prefixes ...string) bool {
	for _, pfx := range prefixes {
		if name == pfx || strings.HasPrefix(name, pfx+"-") || strings.HasPrefix(name, pfx+".") {
			return true
		}
	}
	return false
}

// Search returns all models matching provider and optional query substring.
func Search(prov domain.ProviderType, query string) []*domain.GlobalModel {
	EnsureLoaded()
	var out []*domain.GlobalModel
	q := strings.ToLower(strings.TrimSpace(query))
	var p string
	if prov != "" {
		p = strings.ToLower(string(config.NormalizeProvider(string(prov))))
	}

	for _, m := range catalogList {
		if p != "" && strings.ToLower(string(m.Provider)) != p {
			continue
		}
		if q != "" && !strings.Contains(strings.ToLower(m.ModelName), q) && !strings.Contains(strings.ToLower(m.DisplayName), q) {
			continue
		}
		cp := *m
		out = append(out, &cp)
	}
	return out
}
