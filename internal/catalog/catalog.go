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
	switch norm {
	case domain.ProviderOpenAI,
		domain.ProviderAnthropic,
		domain.ProviderGemini,
		domain.ProviderMistral,
		domain.ProviderOllama,
		domain.ProviderAzure,
		domain.ProviderBedrock,
		domain.ProviderVertex,
		domain.ProviderCohere,
		domain.ProviderCerebras,
		domain.ProviderSambaNova,
		domain.ProviderXAI,
		domain.ProviderTogether,
		domain.ProviderFireworks,
		domain.ProviderGroq,
		domain.ProviderDeepSeek,
		domain.ProviderPerplexity,
		domain.ProviderAnyscale,
		domain.ProviderDeepInfra,
		domain.ProviderNovita,
		domain.ProviderNebius,
		domain.ProviderHyperbolic,
		domain.ProviderLambda,
		domain.ProviderFriendli,
		domain.ProviderOpenRouter,
		domain.ProviderVLLM,
		domain.ProviderCloudflare,
		domain.ProviderDatabricks,
		domain.ProviderSnowflake,
		domain.ProviderDashScope,
		domain.ProviderVolcengine,
		domain.ProviderBigModel,
		domain.ProviderMoonshot,
		domain.ProviderMiniMax,
		domain.ProviderSiliconFlow,
		domain.ProviderVoyage,
		domain.ProviderJina,
		domain.ProviderReplicate,
		domain.ProviderAI21,
		domain.ProviderBaseten,
		domain.ProviderNvidia,
		domain.ProviderScaleway:
		return true
	default:
		return false
	}
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
		return &cp, true
	}
	lower := strings.ToLower(clean)
	if m, ok := modelsByID[lower]; ok {
		cp := *m
		return &cp, true
	}
	if idx := strings.IndexByte(clean, '/'); idx > 0 {
		normProv := config.NormalizeProvider(clean[:idx])
		bareModel := clean[idx+1:]
		pnKey := fmt.Sprintf("%s/%s", strings.ToLower(string(normProv)), strings.ToLower(bareModel))
		if m, ok := modelsByPN[pnKey]; ok {
			cp := *m
			return &cp, true
		}
	} else {
		if m, ok := modelsByName[lower]; ok {
			cp := *m
			return &cp, true
		}
	}
	return nil, false
}

// LookupByProviderAndModel finds a model by its provider and model name,
// automatically normalizing provider aliases (e.g. "vertex_ai" -> "vertex", "bedrock_converse" -> "bedrock").
func LookupByProviderAndModel(prov domain.ProviderType, modelName string) (*domain.GlobalModel, bool) {
	EnsureLoaded()
	normProv := config.NormalizeProvider(string(prov))
	cleanModel := strings.TrimSpace(modelName)
	pnKey := fmt.Sprintf("%s/%s", strings.ToLower(string(normProv)), strings.ToLower(cleanModel))
	if m, ok := modelsByPN[pnKey]; ok {
		cp := *m
		return &cp, true
	}
	// Try direct lookup with normalized provider
	return Lookup(fmt.Sprintf("%s/%s", normProv, cleanModel))
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
