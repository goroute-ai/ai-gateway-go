package main

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
)

type seedModelEntry struct {
	MaxTokens                    int     `json:"max_tokens"`
	MaxInputTokens               int     `json:"max_input_tokens"`
	MaxOutputTokens              int     `json:"max_output_tokens"`
	InputCostPerToken            float64 `json:"input_cost_per_token"`
	OutputCostPerToken           float64 `json:"output_cost_per_token"`
	OutputCostPerReasoningToken  float64 `json:"output_cost_per_reasoning_token"`
	InputCostPerImage            float64 `json:"input_cost_per_image"`
	CacheReadInputTokenCost      float64 `json:"cache_read_input_token_cost"`
	CacheCreationInputTokenCost  float64 `json:"cache_creation_input_token_cost"`
	OutputCostPerImage           float64 `json:"output_cost_per_image"`
	InputCostPerSecond           float64 `json:"input_cost_per_second"`
	InputCostPerAudioPerSecond   float64 `json:"input_cost_per_audio_per_second"`
	InputCostPerCharacter        float64 `json:"input_cost_per_character"`
	InputCostPerQuery            float64 `json:"input_cost_per_query"`
	Provider                     string  `json:"-"`
	Mode                         string  `json:"mode"`
	SupportsFunctionCalling      *bool   `json:"supports_function_calling"`
	SupportsParallelFunctionCall *bool   `json:"supports_parallel_function_calling"`
	SupportsVision               *bool   `json:"supports_vision"`
	SupportsReasoning            *bool   `json:"supports_reasoning"`
	SupportsPromptCaching        *bool   `json:"supports_prompt_caching"`
	SupportsResponseSchema       *bool   `json:"supports_response_schema"`
	SupportsAudioInput           *bool   `json:"supports_audio_input"`
	SupportsAudioOutput          *bool   `json:"supports_audio_output"`
	SupportsNativeStreaming      *bool   `json:"supports_native_streaming"`
	Source                       string  `json:"source"`
	DeprecationDate              string  `json:"deprecation_date"`
}

func (e *seedModelEntry) UnmarshalJSON(b []byte) error {
	type alias seedModelEntry
	var a alias
	if err := json.Unmarshal(b, &a); err != nil {
		return err
	}
	*e = seedModelEntry(a)

	var rawFields map[string]any
	if err := json.Unmarshal(b, &rawFields); err == nil {
		for k, v := range rawFields {
			if strings.HasSuffix(k, "_provider") || k == "provider" {
				if s, ok := v.(string); ok && s != "" {
					e.Provider = s
					break
				}
			}
		}
	}
	return nil
}

func main() {
	sourcePath := flag.String("source", "model_prices_and_context_window.json", "Path to source model definitions JSON")
	outPath := flag.String("out", "internal/modelcatalog/catalog.json.gz", "Path to output catalog.json.gz")
	flag.Parse()

	data, err := os.ReadFile(*sourcePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to read source file: %v\n", err)
		os.Exit(1)
	}

	var rawMap map[string]json.RawMessage
	if err := json.Unmarshal(data, &rawMap); err != nil {
		fmt.Fprintf(os.Stderr, "failed to parse source JSON: %v\n", err)
		os.Exit(1)
	}

	catalogModels := make(map[string]*domain.GlobalModel)
	imageVariantRates := make(map[string]map[string]int64)
	now := time.Now().UTC()

	for rawKey, rawVal := range rawMap {
		if rawKey == "sample_spec" {
			continue
		}
		var entry seedModelEntry
		if err := json.Unmarshal(rawVal, &entry); err != nil {
			continue
		}
		if entry.Mode == "image_generation" && entry.Provider != "" {
			provider := config.NormalizeProvider(entry.Provider)
			if modelName, rateKey, ok := parseImagePriceVariant(rawKey, provider); ok {
				rate := int64(math.Round(math.Max(entry.InputCostPerImage, entry.OutputCostPerImage) * 1e6))
				if rate > 0 {
					globalID := fmt.Sprintf("%s/%s", provider, modelName)
					if imageVariantRates[globalID] == nil {
						imageVariantRates[globalID] = make(map[string]int64)
					}
					if rate > imageVariantRates[globalID][rateKey] {
						imageVariantRates[globalID][rateKey] = rate
					}
				}
				continue
			}
		}

		var prov domain.ProviderType
		var bareModel string
		var globalID string

		qualityOrDimPrefixes := []string{"1024-x-", "512-x-", "1536-x-", "256-x-", "1792-x-", "max-x-max/", "hd/", "high/", "low/", "medium/", "standard/", "xhigh/", "max/"}
		isQualityOrDim := false
		for _, pfx := range qualityOrDimPrefixes {
			if strings.HasPrefix(rawKey, pfx) {
				isQualityOrDim = true
				break
			}
		}

		if isQualityOrDim && entry.Provider != "" {
			prov = config.NormalizeProvider(entry.Provider)
			bareModel = rawKey
		} else if idx := strings.IndexByte(rawKey, '/'); idx > 0 {
			rawProv := rawKey[:idx]
			normKeyProv := config.NormalizeProvider(rawProv)
			if entry.Provider != "" {
				entryProv := config.NormalizeProvider(entry.Provider)
				prov = entryProv
				if normKeyProv == entryProv || config.IsKnownProviderAlias(rawProv) {
					bareModel = rawKey[idx+1:]
				} else {
					bareModel = rawKey
				}
			} else {
				prov = normKeyProv
				bareModel = rawKey[idx+1:]
			}
		} else if entry.Provider != "" {
			prov = config.NormalizeProvider(entry.Provider)
			bareModel = rawKey
		} else {
			prov, bareModel, _ = config.ParseProviderModel(rawKey)
		}

		if prov == "" {
			continue
		}
		if bareModel == "" {
			bareModel = rawKey
		}
		globalID = fmt.Sprintf("%s/%s", prov, bareModel)

		maxIn := entry.MaxInputTokens
		if maxIn <= 0 {
			maxIn = entry.MaxTokens
		}
		if maxIn <= 0 {
			maxIn = 8192
		}
		maxOut := entry.MaxOutputTokens
		if maxOut <= 0 {
			maxOut = 4096
		}

		inCostMicros := int64(math.Round(entry.InputCostPerToken * 1e12))
		outCostMicros := int64(math.Round(entry.OutputCostPerToken * 1e12))
		cachedCostMicros := int64(math.Round(entry.CacheReadInputTokenCost * 1e12))
		cacheWriteCostMicros := int64(math.Round(entry.CacheCreationInputTokenCost * 1e12))
		reasoningCostMicros := int64(math.Round(entry.OutputCostPerReasoningToken * 1e12))

		var rerankCostMicros, imageCostMicrosBase, audioSTTCostMicros, audioTTSCostMicros int64
		if entry.Mode == "rerank" && entry.InputCostPerQuery > 0 {
			rerankCostMicros = int64(math.Round(entry.InputCostPerQuery * 1e6))
		}
		if (entry.Mode == "image_generation" || entry.Mode == "image_edit") && (entry.InputCostPerImage > 0 || entry.OutputCostPerImage > 0) {
			imageCostMicrosBase = int64(math.Round(math.Max(entry.InputCostPerImage, entry.OutputCostPerImage) * 1e6))
		}
		if entry.Mode == "audio_transcription" {
			secRate := entry.InputCostPerSecond
			if secRate <= 0 {
				secRate = entry.InputCostPerAudioPerSecond
			}
			if secRate > 0 {
				audioSTTCostMicros = int64(math.Round(secRate * 1e6))
			}
		}
		if entry.Mode == "audio_speech" && entry.InputCostPerCharacter > 0 {
			audioTTSCostMicros = int64(math.Round(entry.InputCostPerCharacter * 1e9))
		}

		// Imported upstream catalog prices remain unverified (PricingStatusUnknown)
		// until explicitly approved by an operator or custom pricing policy.
		pricingStatus := domain.PricingStatusUnknown
		if inCostMicros == 0 && outCostMicros == 0 && rerankCostMicros == 0 && imageCostMicrosBase == 0 && audioSTTCostMicros == 0 && audioTTSCostMicros == 0 {
			pricingStatus = domain.PricingStatusUnrecorded
		}

		caps := domain.ModelCapabilities{
			Tools:             domain.CapabilityUnknown,
			Streaming:         domain.CapabilitySupported,
			Vision:            domain.CapabilityUnknown,
			Reasoning:         domain.CapabilityUnknown,
			StructuredOutputs: domain.CapabilityUnknown,
			Embeddings:        domain.CapabilityUnknown,
			Rerank:            domain.CapabilityUnknown,
			Moderation:        domain.CapabilityUnknown,
			ImageGen:          domain.CapabilityUnknown,
			AudioSTT:          domain.CapabilityUnknown,
			AudioTTS:          domain.CapabilityUnknown,
			Batches:           domain.CapabilityUnknown,
			Realtime:          domain.CapabilityUnknown,
		}
		if entry.SupportsNativeStreaming != nil && !*entry.SupportsNativeStreaming {
			caps.Streaming = domain.CapabilityUnsupported
		}
		if entry.SupportsFunctionCalling != nil {
			if *entry.SupportsFunctionCalling {
				caps.Tools = domain.CapabilitySupported
			} else {
				caps.Tools = domain.CapabilityUnsupported
			}
		}
		if entry.SupportsParallelFunctionCall != nil && *entry.SupportsParallelFunctionCall {
			caps.Tools = domain.CapabilitySupported
		}
		if entry.SupportsVision != nil {
			if *entry.SupportsVision {
				caps.Vision = domain.CapabilitySupported
			} else {
				caps.Vision = domain.CapabilityUnsupported
			}
		}
		if entry.SupportsReasoning != nil {
			if *entry.SupportsReasoning {
				caps.Reasoning = domain.CapabilitySupported
			} else {
				caps.Reasoning = domain.CapabilityUnsupported
			}
		}
		if entry.SupportsResponseSchema != nil {
			if *entry.SupportsResponseSchema {
				caps.StructuredOutputs = domain.CapabilitySupported
			} else {
				caps.StructuredOutputs = domain.CapabilityUnsupported
			}
		}
		if entry.SupportsAudioInput != nil && *entry.SupportsAudioInput {
			caps.AudioSTT = domain.CapabilitySupported
		}
		if entry.SupportsAudioOutput != nil && *entry.SupportsAudioOutput {
			caps.AudioTTS = domain.CapabilitySupported
		}

		var supportedOps []domain.OperationType
		switch entry.Mode {
		case "chat", "":
			supportedOps = []domain.OperationType{domain.OperationChat}
		case "completion":
			supportedOps = []domain.OperationType{domain.OperationCompletion}
		case "responses":
			// The gateway's Responses API currently translates through canonical chat
			// execution, so these models must also pass chat-operation routing checks.
			supportedOps = []domain.OperationType{domain.OperationChat, domain.OperationResponses}
		case "embedding":
			caps.Embeddings = domain.CapabilitySupported
			supportedOps = []domain.OperationType{domain.OperationEmbedding}
		case "rerank":
			caps.Rerank = domain.CapabilitySupported
			supportedOps = []domain.OperationType{domain.OperationRerank}
		case "moderation":
			caps.Moderation = domain.CapabilitySupported
			supportedOps = []domain.OperationType{domain.OperationModeration}
		case "image_generation":
			caps.ImageGen = domain.CapabilitySupported
			supportedOps = []domain.OperationType{domain.OperationImageGeneration}
		case "image_edit":
			caps.ImageGen = domain.CapabilitySupported
			supportedOps = []domain.OperationType{domain.OperationImageEdit}
		case "image_variation":
			supportedOps = []domain.OperationType{domain.OperationImageVariation}
		case "audio_transcription":
			caps.AudioSTT = domain.CapabilitySupported
			supportedOps = []domain.OperationType{domain.OperationAudioSTT}
		case "audio_speech":
			caps.AudioTTS = domain.CapabilitySupported
			supportedOps = []domain.OperationType{domain.OperationAudioTTS}
		case "realtime":
			caps.Realtime = domain.CapabilitySupported
			supportedOps = []domain.OperationType{domain.OperationRealtime}
		}

		var deprecationDate *time.Time
		if entry.DeprecationDate != "" {
			if dt, err := time.Parse("2006-01-02", entry.DeprecationDate); err == nil {
				deprecationDate = &dt
			}
		}

		supportsInference := entry.Mode == "chat" || entry.Mode == "completion" || entry.Mode == "responses" || entry.Mode == "embedding" || entry.Mode == ""

		gm := &domain.GlobalModel{
			ID:                            globalID,
			Provider:                      prov,
			ModelName:                     bareModel,
			DisplayName:                   fmt.Sprintf("%s (%s)", bareModel, strings.ToUpper(string(prov))),
			MaxInputTokens:                maxIn,
			MaxOutputTokens:               maxOut,
			Capabilities:                  caps,
			SupportedOperations:           supportedOps,
			SupportsStreaming:             caps.Streaming == domain.CapabilitySupported,
			SupportsTools:                 caps.Tools == domain.CapabilitySupported,
			SupportsVision:                caps.Vision == domain.CapabilitySupported,
			SupportsReasoning:             caps.Reasoning == domain.CapabilitySupported,
			SupportsEmbeddings:            caps.Embeddings == domain.CapabilitySupported,
			SupportsInference:             supportsInference,
			InputCostMicrosPer1M:          inCostMicros,
			OutputCostMicrosPer1M:         outCostMicros,
			CachedInputCostMicrosPer1M:    cachedCostMicros,
			CacheWriteCostMicrosPer1M:     cacheWriteCostMicros,
			ReasoningCostMicrosPer1M:      reasoningCostMicros,
			RerankCostMicrosPerSearchUnit: rerankCostMicros,
			ImageCostMicrosBase:           imageCostMicrosBase,
			AudioSTTCostMicrosPerSecond:   audioSTTCostMicros,
			AudioTTSCostMicrosPer1KChars:  audioTTSCostMicros,
			PricingVersion:                1,
			PricingStatus:                 pricingStatus,
			PricingProvenanceSource:       "upstream-model-catalog-v1.1",
			PricingEffectiveDate:          "2026-01-01",
			LifecycleStatus:               domain.ModelStatusActive,
			DeprecationDate:               deprecationDate,
			DiscoveredAt:                  now,
			UpdatedAt:                     now,
		}

		if existing, exists := catalogModels[globalID]; exists {
			if existing.InputCostMicrosPer1M == 0 && inCostMicros > 0 {
				catalogModels[globalID] = gm
			}
			continue
		}
		catalogModels[globalID] = gm
	}

	for id, rates := range imageVariantRates {
		gm := catalogModels[id]
		if gm == nil {
			provider, modelName, _ := config.ParseProviderModel(id)
			gm = &domain.GlobalModel{
				ID:                      id,
				Provider:                provider,
				ModelName:               modelName,
				DisplayName:             fmt.Sprintf("%s (%s)", modelName, strings.ToUpper(string(provider))),
				MaxInputTokens:          8192,
				MaxOutputTokens:         4096,
				Capabilities:            domain.ModelCapabilities{ImageGen: domain.CapabilitySupported},
				SupportedOperations:     []domain.OperationType{domain.OperationImageGeneration},
				PricingVersion:          1,
				PricingStatus:           domain.PricingStatusUnknown,
				PricingProvenanceSource: "upstream-model-catalog-v1.1",
				PricingEffectiveDate:    "2026-01-01",
				LifecycleStatus:         domain.ModelStatusActive,
				DiscoveredAt:            now,
				UpdatedAt:               now,
			}
			catalogModels[id] = gm
		}
		if gm.ModalityPricingJSON == nil {
			gm.ModalityPricingJSON = make(map[string]any)
		}
		for key, rate := range rates {
			gm.ModalityPricingJSON[key] = rate
			if key == "standard_1024x1024" && gm.ImageCostMicrosBase == 0 {
				gm.ImageCostMicrosBase = rate
			}
			if key == "hd_1024x1024" && rate > gm.ImageCostMicrosHD {
				gm.ImageCostMicrosHD = rate
			}
		}
	}

	fmt.Printf("Normalized %d models from source.\n", len(catalogModels))

	marshaled, err := json.Marshal(catalogModels)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to marshal catalog JSON: %v\n", err)
		os.Exit(1)
	}

	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	if _, err := gw.Write(marshaled); err != nil {
		fmt.Fprintf(os.Stderr, "failed to gzip catalog: %v\n", err)
		os.Exit(1)
	}
	if err := gw.Close(); err != nil {
		fmt.Fprintf(os.Stderr, "failed to close gzip: %v\n", err)
		os.Exit(1)
	}

	if err := os.MkdirAll(filepath.Dir(*outPath), 0755); err != nil {
		fmt.Fprintf(os.Stderr, "failed to create out dir: %v\n", err)
		os.Exit(1)
	}

	if err := os.WriteFile(*outPath, buf.Bytes(), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "failed to write output file: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Successfully generated %s (%d bytes, compressed from %d bytes raw).\n", *outPath, buf.Len(), len(marshaled))
}

func parseImagePriceVariant(rawKey string, provider domain.ProviderType) (modelName, rateKey string, ok bool) {
	var quality, size string
	var modelParts []string
	foundQualifier := false
	for i, part := range strings.Split(rawKey, "/") {
		lower := strings.ToLower(part)
		// Some LiteLLM image keys prefix the model path with the provider alias
		// before the quality/size qualifiers (for example, fal_ai/low/...).
		// Remove that namespace so the normalized model ID matches the base row.
		if i == 0 && config.NormalizeProvider(part) == provider && config.IsKnownProviderAlias(part) {
			continue
		}
		switch lower {
		case "standard", "high", "medium", "low", "hd", "xhigh", "max":
			quality = lower
			foundQualifier = true
			continue
		}
		if lower == "max-x-max" || strings.Contains(lower, "-x-") {
			size = strings.ReplaceAll(lower, "-x-", "x")
			foundQualifier = true
			continue
		}
		if strings.HasSuffix(lower, "-steps") {
			foundQualifier = true
			continue
		}
		if foundQualifier && config.NormalizeProvider(part) == provider && config.IsKnownProviderAlias(part) {
			continue
		}
		modelParts = append(modelParts, part)
	}
	if !foundQualifier || size == "" || len(modelParts) == 0 {
		return "", "", false
	}
	if quality == "" {
		quality = "standard"
	}
	return strings.Join(modelParts, "/"), quality + "_" + size, true
}
