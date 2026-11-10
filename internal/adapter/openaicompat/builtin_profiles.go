package openaicompat

import (
	"github.com/goroute-ai/ai-gateway-go/internal/adapter"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
)

// registerBuiltinProfiles registers certified OpenAI-compatible dialect profiles
// for major production providers across the AI ecosystem.
func (r *ProfileRegistry) registerBuiltinProfiles() {
	standardParamMap := map[string]string{
		"max_completion_tokens": "max_tokens",
	}

	// 1. Cerebras (Ultra-fast wafer-scale Llama/DeepSeek inference)
	r.profiles[domain.ProviderCerebras] = &DialectProfile{
		ID:                 domain.ProviderCerebras,
		DisplayName:        "Cerebras Wafer-Scale Engine",
		DefaultBaseURL:     "https://api.cerebras.ai/v1",
		EndpointStrategy:   &adapter.StandardOpenAIEndpointStrategy{DefaultBaseURL: "https://api.cerebras.ai/v1"},
		AuthStrategy:       &adapter.BearerAuthStrategy{},
		SupportsListModels: true,
		ParamMappings:      standardParamMap,
		DefaultCapabilities: domain.ModelCapabilities{
			Tools:             domain.CapabilitySupported,
			Streaming:         domain.CapabilitySupported,
			StructuredOutputs: domain.CapabilitySupported,
		},
	}

	// 2. SambaNova Systems (DataScale high-throughput inference)
	r.profiles[domain.ProviderSambaNova] = &DialectProfile{
		ID:                    domain.ProviderSambaNova,
		DisplayName:           "SambaNova Systems",
		DefaultBaseURL:        "https://api.sambanova.ai/v1",
		EndpointStrategy:      &adapter.StandardOpenAIEndpointStrategy{DefaultBaseURL: "https://api.sambanova.ai/v1"},
		AuthStrategy:          &adapter.BearerAuthStrategy{},
		SupportsListModels:    true,
		ExtractReasoningDelta: true,
		ParamMappings:         standardParamMap,
		DefaultCapabilities: domain.ModelCapabilities{
			Tools:             domain.CapabilitySupported,
			Streaming:         domain.CapabilitySupported,
			Reasoning:         domain.CapabilitySupported,
			StructuredOutputs: domain.CapabilitySupported,
		},
	}

	// 3. xAI (Grok models)
	r.profiles[domain.ProviderXAI] = &DialectProfile{
		ID:                    domain.ProviderXAI,
		DisplayName:           "xAI (Grok)",
		DefaultBaseURL:        "https://api.x.ai/v1",
		EndpointStrategy:      &adapter.StandardOpenAIEndpointStrategy{DefaultBaseURL: "https://api.x.ai/v1"},
		AuthStrategy:          &adapter.BearerAuthStrategy{},
		SupportsListModels:    true,
		ExtractReasoningDelta: true,
		ParamMappings:         standardParamMap,
		DefaultCapabilities: domain.ModelCapabilities{
			Tools:             domain.CapabilitySupported,
			Streaming:         domain.CapabilitySupported,
			Vision:            domain.CapabilitySupported,
			Reasoning:         domain.CapabilitySupported,
			StructuredOutputs: domain.CapabilitySupported,
		},
	}

	// 4. Fireworks AI (Fast serverless inference & fine-tuning)
	r.profiles[domain.ProviderFireworks] = &DialectProfile{
		ID:                 domain.ProviderFireworks,
		DisplayName:        "Fireworks AI",
		DefaultBaseURL:     "https://api.fireworks.ai/inference/v1",
		EndpointStrategy:   &adapter.StandardOpenAIEndpointStrategy{DefaultBaseURL: "https://api.fireworks.ai/inference/v1"},
		AuthStrategy:       &adapter.BearerAuthStrategy{},
		SupportsListModels: true,
		ParamMappings:      standardParamMap,
		DefaultCapabilities: domain.ModelCapabilities{
			Tools:             domain.CapabilitySupported,
			Streaming:         domain.CapabilitySupported,
			Vision:            domain.CapabilitySupported,
			Embeddings:        domain.CapabilitySupported,
			StructuredOutputs: domain.CapabilitySupported,
		},
	}

	// 5. Perplexity AI (Sonar search & generation)
	r.profiles[domain.ProviderPerplexity] = &DialectProfile{
		ID:                 domain.ProviderPerplexity,
		DisplayName:        "Perplexity AI",
		DefaultBaseURL:     "https://api.perplexity.ai",
		EndpointStrategy:   &adapter.StandardOpenAIEndpointStrategy{DefaultBaseURL: "https://api.perplexity.ai"},
		AuthStrategy:       &adapter.BearerAuthStrategy{},
		SupportsListModels: false,
		ParamMappings:      standardParamMap,
		DefaultCapabilities: domain.ModelCapabilities{
			Tools:     domain.CapabilityUnsupported,
			Streaming: domain.CapabilitySupported,
		},
	}

	// 6. Anyscale Endpoints
	r.profiles[domain.ProviderAnyscale] = &DialectProfile{
		ID:                 domain.ProviderAnyscale,
		DisplayName:        "Anyscale Endpoints",
		DefaultBaseURL:     "https://api.endpoints.anyscale.com/v1",
		EndpointStrategy:   &adapter.StandardOpenAIEndpointStrategy{DefaultBaseURL: "https://api.endpoints.anyscale.com/v1"},
		AuthStrategy:       &adapter.BearerAuthStrategy{},
		SupportsListModels: true,
		ParamMappings:      standardParamMap,
		DefaultCapabilities: domain.ModelCapabilities{
			Tools:             domain.CapabilitySupported,
			Streaming:         domain.CapabilitySupported,
			Embeddings:        domain.CapabilitySupported,
			StructuredOutputs: domain.CapabilitySupported,
		},
	}

	// 7. DeepInfra
	r.profiles[domain.ProviderDeepInfra] = &DialectProfile{
		ID:                 domain.ProviderDeepInfra,
		DisplayName:        "DeepInfra",
		DefaultBaseURL:     "https://api.deepinfra.com/v1/openai",
		EndpointStrategy:   &adapter.StandardOpenAIEndpointStrategy{DefaultBaseURL: "https://api.deepinfra.com/v1/openai"},
		AuthStrategy:       &adapter.BearerAuthStrategy{},
		SupportsListModels: true,
		ParamMappings:      standardParamMap,
		DefaultCapabilities: domain.ModelCapabilities{
			Tools:             domain.CapabilitySupported,
			Streaming:         domain.CapabilitySupported,
			Embeddings:        domain.CapabilitySupported,
			StructuredOutputs: domain.CapabilitySupported,
		},
	}

	// 8. Novita AI
	r.profiles[domain.ProviderNovita] = &DialectProfile{
		ID:                    domain.ProviderNovita,
		DisplayName:           "Novita AI",
		DefaultBaseURL:        "https://api.novita.ai/v3/openai",
		EndpointStrategy:      &adapter.StandardOpenAIEndpointStrategy{DefaultBaseURL: "https://api.novita.ai/v3/openai"},
		AuthStrategy:          &adapter.BearerAuthStrategy{},
		SupportsListModels:    true,
		ExtractReasoningDelta: true,
		ParamMappings:         standardParamMap,
		DefaultCapabilities: domain.ModelCapabilities{
			Tools:             domain.CapabilitySupported,
			Streaming:         domain.CapabilitySupported,
			Reasoning:         domain.CapabilitySupported,
			Embeddings:        domain.CapabilitySupported,
			StructuredOutputs: domain.CapabilitySupported,
		},
	}

	// 9. Nebius AI Studio
	r.profiles[domain.ProviderNebius] = &DialectProfile{
		ID:                    domain.ProviderNebius,
		DisplayName:           "Nebius AI Studio",
		DefaultBaseURL:        "https://api.studio.nebius.ai/v1",
		EndpointStrategy:      &adapter.StandardOpenAIEndpointStrategy{DefaultBaseURL: "https://api.studio.nebius.ai/v1"},
		AuthStrategy:          &adapter.BearerAuthStrategy{},
		SupportsListModels:    true,
		ExtractReasoningDelta: true,
		ParamMappings:         standardParamMap,
		DefaultCapabilities: domain.ModelCapabilities{
			Tools:             domain.CapabilitySupported,
			Streaming:         domain.CapabilitySupported,
			Reasoning:         domain.CapabilitySupported,
			StructuredOutputs: domain.CapabilitySupported,
		},
	}

	// 10. Hyperbolic
	r.profiles[domain.ProviderHyperbolic] = &DialectProfile{
		ID:                    domain.ProviderHyperbolic,
		DisplayName:           "Hyperbolic AI",
		DefaultBaseURL:        "https://api.hyperbolic.xyz/v1",
		EndpointStrategy:      &adapter.StandardOpenAIEndpointStrategy{DefaultBaseURL: "https://api.hyperbolic.xyz/v1"},
		AuthStrategy:          &adapter.BearerAuthStrategy{},
		SupportsListModels:    true,
		ExtractReasoningDelta: true,
		ParamMappings:         standardParamMap,
		DefaultCapabilities: domain.ModelCapabilities{
			Tools:             domain.CapabilitySupported,
			Streaming:         domain.CapabilitySupported,
			Reasoning:         domain.CapabilitySupported,
			StructuredOutputs: domain.CapabilitySupported,
		},
	}

	// 11. Lambda Labs
	r.profiles[domain.ProviderLambda] = &DialectProfile{
		ID:                 domain.ProviderLambda,
		DisplayName:        "Lambda Labs Inference",
		DefaultBaseURL:     "https://api.lambdalabs.com/v1",
		EndpointStrategy:   &adapter.StandardOpenAIEndpointStrategy{DefaultBaseURL: "https://api.lambdalabs.com/v1"},
		AuthStrategy:       &adapter.BearerAuthStrategy{},
		SupportsListModels: true,
		ParamMappings:      standardParamMap,
		DefaultCapabilities: domain.ModelCapabilities{
			Tools:     domain.CapabilitySupported,
			Streaming: domain.CapabilitySupported,
		},
	}

	// 12. Friendli AI
	r.profiles[domain.ProviderFriendli] = &DialectProfile{
		ID:                 domain.ProviderFriendli,
		DisplayName:        "Friendli AI",
		DefaultBaseURL:     "https://inference.friendli.ai/v1",
		EndpointStrategy:   &adapter.StandardOpenAIEndpointStrategy{DefaultBaseURL: "https://inference.friendli.ai/v1"},
		AuthStrategy:       &adapter.BearerAuthStrategy{},
		SupportsListModels: true,
		ParamMappings:      standardParamMap,
		DefaultCapabilities: domain.ModelCapabilities{
			Tools:             domain.CapabilitySupported,
			Streaming:         domain.CapabilitySupported,
			StructuredOutputs: domain.CapabilitySupported,
		},
	}

	// 13. OpenRouter (Universal AI Model Router)
	r.profiles[domain.ProviderOpenRouter] = &DialectProfile{
		ID:                    domain.ProviderOpenRouter,
		DisplayName:           "OpenRouter",
		DefaultBaseURL:        "https://openrouter.ai/api/v1",
		EndpointStrategy:      &adapter.StandardOpenAIEndpointStrategy{DefaultBaseURL: "https://openrouter.ai/api/v1"},
		AuthStrategy:          &adapter.BearerAuthStrategy{},
		SupportsListModels:    true,
		ExtractReasoningDelta: true,
		ParamMappings:         standardParamMap,
		DefaultCapabilities: domain.ModelCapabilities{
			Tools:             domain.CapabilitySupported,
			Streaming:         domain.CapabilitySupported,
			Vision:            domain.CapabilitySupported,
			Reasoning:         domain.CapabilitySupported,
			StructuredOutputs: domain.CapabilitySupported,
		},
	}

	// 14. vLLM (Self-hosted engine)
	r.profiles[domain.ProviderVLLM] = &DialectProfile{
		ID:                 domain.ProviderVLLM,
		DisplayName:        "vLLM Local / Self-Hosted",
		DefaultBaseURL:     "http://localhost:8000/v1",
		EndpointStrategy:   &adapter.StandardOpenAIEndpointStrategy{DefaultBaseURL: "http://localhost:8000/v1"},
		AuthStrategy:       &adapter.BearerAuthStrategy{},
		SupportsListModels: true,
		ParamMappings:      standardParamMap,
		DefaultCapabilities: domain.ModelCapabilities{
			Tools:             domain.CapabilitySupported,
			Streaming:         domain.CapabilitySupported,
			Embeddings:        domain.CapabilitySupported,
			StructuredOutputs: domain.CapabilitySupported,
		},
	}

	// 15. Cloudflare Workers AI
	r.profiles[domain.ProviderCloudflare] = &DialectProfile{
		ID:                 domain.ProviderCloudflare,
		DisplayName:        "Cloudflare Workers AI",
		DefaultBaseURL:     "https://api.cloudflare.com/client/v4/ai/v1",
		EndpointStrategy:   &adapter.StandardOpenAIEndpointStrategy{DefaultBaseURL: "https://api.cloudflare.com/client/v4/ai/v1"},
		AuthStrategy:       &adapter.BearerAuthStrategy{},
		SupportsListModels: false,
		ParamMappings:      standardParamMap,
		DefaultCapabilities: domain.ModelCapabilities{
			Tools:      domain.CapabilitySupported,
			Streaming:  domain.CapabilitySupported,
			Embeddings: domain.CapabilitySupported,
		},
	}

	// 16. Databricks Model Serving
	r.profiles[domain.ProviderDatabricks] = &DialectProfile{
		ID:                 domain.ProviderDatabricks,
		DisplayName:        "Databricks Model Serving",
		DefaultBaseURL:     "",
		EndpointStrategy:   &adapter.StandardOpenAIEndpointStrategy{DefaultBaseURL: ""},
		AuthStrategy:       &adapter.BearerAuthStrategy{},
		SupportsListModels: false,
		ParamMappings:      standardParamMap,
		DefaultCapabilities: domain.ModelCapabilities{
			Tools:             domain.CapabilitySupported,
			Streaming:         domain.CapabilitySupported,
			Embeddings:        domain.CapabilitySupported,
			StructuredOutputs: domain.CapabilitySupported,
		},
	}

	// 17. Snowflake Cortex
	r.profiles[domain.ProviderSnowflake] = &DialectProfile{
		ID:                 domain.ProviderSnowflake,
		DisplayName:        "Snowflake Cortex REST API",
		DefaultBaseURL:     "",
		EndpointStrategy:   &adapter.StandardOpenAIEndpointStrategy{DefaultBaseURL: ""},
		AuthStrategy:       &adapter.BearerAuthStrategy{},
		SupportsListModels: false,
		ParamMappings:      standardParamMap,
		DefaultCapabilities: domain.ModelCapabilities{
			Tools:      domain.CapabilitySupported,
			Streaming:  domain.CapabilitySupported,
			Embeddings: domain.CapabilitySupported,
		},
	}

	// 18. DashScope (Alibaba Cloud / Qwen)
	r.profiles[domain.ProviderDashScope] = &DialectProfile{
		ID:                 domain.ProviderDashScope,
		DisplayName:        "Alibaba Cloud DashScope (Qwen)",
		DefaultBaseURL:     "https://dashscope.aliyuncs.com/compatible-mode/v1",
		EndpointStrategy:   &adapter.StandardOpenAIEndpointStrategy{DefaultBaseURL: "https://dashscope.aliyuncs.com/compatible-mode/v1"},
		AuthStrategy:       &adapter.BearerAuthStrategy{},
		SupportsListModels: true,
		ParamMappings:      standardParamMap,
		DefaultCapabilities: domain.ModelCapabilities{
			Tools:             domain.CapabilitySupported,
			Streaming:         domain.CapabilitySupported,
			Vision:            domain.CapabilitySupported,
			Embeddings:        domain.CapabilitySupported,
			StructuredOutputs: domain.CapabilitySupported,
		},
	}

	// 19. Volcengine (ByteDance Doubao)
	volcengineTempRange := [2]float64{0.0, 1.0}
	r.profiles[domain.ProviderVolcengine] = &DialectProfile{
		ID:                    domain.ProviderVolcengine,
		DisplayName:           "ByteDance Volcengine (Doubao)",
		DefaultBaseURL:        "https://ark.cn-beijing.volces.com/api/v3",
		EndpointStrategy:      &adapter.StandardOpenAIEndpointStrategy{DefaultBaseURL: "https://ark.cn-beijing.volces.com/api/v3"},
		AuthStrategy:          &adapter.BearerAuthStrategy{},
		SupportsListModels:    false,
		ExtractReasoningDelta: true,
		ParamMappings:         standardParamMap,
		Constraints: DialectConstraints{
			SupportedTemperature: &volcengineTempRange,
		},
		DefaultCapabilities: domain.ModelCapabilities{
			Tools:             domain.CapabilitySupported,
			Streaming:         domain.CapabilitySupported,
			Vision:            domain.CapabilitySupported,
			Reasoning:         domain.CapabilitySupported,
			StructuredOutputs: domain.CapabilitySupported,
		},
	}

	// 20. BigModel (Zhipu AI / GLM)
	r.profiles[domain.ProviderBigModel] = &DialectProfile{
		ID:                 domain.ProviderBigModel,
		DisplayName:        "Zhipu AI BigModel (GLM)",
		DefaultBaseURL:     "https://open.bigmodel.cn/api/paas/v4",
		EndpointStrategy:   &adapter.StandardOpenAIEndpointStrategy{DefaultBaseURL: "https://open.bigmodel.cn/api/paas/v4"},
		AuthStrategy:       &adapter.BearerAuthStrategy{},
		SupportsListModels: false,
		ParamMappings:      standardParamMap,
		DefaultCapabilities: domain.ModelCapabilities{
			Tools:             domain.CapabilitySupported,
			Streaming:         domain.CapabilitySupported,
			Vision:            domain.CapabilitySupported,
			Embeddings:        domain.CapabilitySupported,
			StructuredOutputs: domain.CapabilitySupported,
		},
	}

	// 21. Moonshot AI (Kimi)
	r.profiles[domain.ProviderMoonshot] = &DialectProfile{
		ID:                 domain.ProviderMoonshot,
		DisplayName:        "Moonshot AI (Kimi)",
		DefaultBaseURL:     "https://api.moonshot.cn/v1",
		EndpointStrategy:   &adapter.StandardOpenAIEndpointStrategy{DefaultBaseURL: "https://api.moonshot.cn/v1"},
		AuthStrategy:       &adapter.BearerAuthStrategy{},
		SupportsListModels: true,
		ParamMappings:      standardParamMap,
		DefaultCapabilities: domain.ModelCapabilities{
			Tools:             domain.CapabilitySupported,
			Streaming:         domain.CapabilitySupported,
			StructuredOutputs: domain.CapabilitySupported,
		},
	}

	// 22. MiniMax
	r.profiles[domain.ProviderMiniMax] = &DialectProfile{
		ID:                    domain.ProviderMiniMax,
		DisplayName:           "MiniMax",
		DefaultBaseURL:        "https://api.minimax.chat/v1",
		EndpointStrategy:      &adapter.StandardOpenAIEndpointStrategy{DefaultBaseURL: "https://api.minimax.chat/v1"},
		AuthStrategy:          &adapter.BearerAuthStrategy{},
		SupportsListModels:    false,
		ExtractReasoningDelta: true,
		ParamMappings:         standardParamMap,
		DefaultCapabilities: domain.ModelCapabilities{
			Tools:             domain.CapabilitySupported,
			Streaming:         domain.CapabilitySupported,
			Reasoning:         domain.CapabilitySupported,
			StructuredOutputs: domain.CapabilitySupported,
		},
	}

	// 23. SiliconFlow
	r.profiles[domain.ProviderSiliconFlow] = &DialectProfile{
		ID:                    domain.ProviderSiliconFlow,
		DisplayName:           "SiliconFlow",
		DefaultBaseURL:        "https://api.siliconflow.cn/v1",
		EndpointStrategy:      &adapter.StandardOpenAIEndpointStrategy{DefaultBaseURL: "https://api.siliconflow.cn/v1"},
		AuthStrategy:          &adapter.BearerAuthStrategy{},
		SupportsListModels:    true,
		ExtractReasoningDelta: true,
		ParamMappings:         standardParamMap,
		DefaultCapabilities: domain.ModelCapabilities{
			Tools:             domain.CapabilitySupported,
			Streaming:         domain.CapabilitySupported,
			Embeddings:        domain.CapabilitySupported,
			Reasoning:         domain.CapabilitySupported,
			StructuredOutputs: domain.CapabilitySupported,
		},
	}

	// 24. Voyage AI (Dedicated Embeddings)
	r.profiles[domain.ProviderVoyage] = &DialectProfile{
		ID:                 domain.ProviderVoyage,
		DisplayName:        "Voyage AI",
		DefaultBaseURL:     "https://api.voyageai.com/v1",
		EndpointStrategy:   &adapter.StandardOpenAIEndpointStrategy{DefaultBaseURL: "https://api.voyageai.com/v1"},
		AuthStrategy:       &adapter.BearerAuthStrategy{},
		SupportsListModels: false,
		DefaultCapabilities: domain.ModelCapabilities{
			Tools:      domain.CapabilityUnsupported,
			Streaming:  domain.CapabilityUnsupported,
			Embeddings: domain.CapabilitySupported,
		},
	}

	// 25. Jina AI (Embeddings & Reranking)
	r.profiles[domain.ProviderJina] = &DialectProfile{
		ID:                 domain.ProviderJina,
		DisplayName:        "Jina AI",
		DefaultBaseURL:     "https://api.jina.ai/v1",
		EndpointStrategy:   &adapter.StandardOpenAIEndpointStrategy{DefaultBaseURL: "https://api.jina.ai/v1"},
		AuthStrategy:       &adapter.BearerAuthStrategy{},
		SupportsListModels: false,
		DefaultCapabilities: domain.ModelCapabilities{
			Tools:      domain.CapabilityUnsupported,
			Streaming:  domain.CapabilityUnsupported,
			Embeddings: domain.CapabilitySupported,
		},
	}

	// 26. Replicate
	r.profiles[domain.ProviderReplicate] = &DialectProfile{
		ID:                 domain.ProviderReplicate,
		DisplayName:        "Replicate Deployments",
		DefaultBaseURL:     "https://api.replicate.com/v1",
		EndpointStrategy:   &adapter.StandardOpenAIEndpointStrategy{DefaultBaseURL: "https://api.replicate.com/v1"},
		AuthStrategy:       &adapter.BearerAuthStrategy{},
		SupportsListModels: false,
		ParamMappings:      standardParamMap,
		DefaultCapabilities: domain.ModelCapabilities{
			Tools:     domain.CapabilitySupported,
			Streaming: domain.CapabilitySupported,
		},
	}

	// 27. AI21 Labs (Jamba)
	r.profiles[domain.ProviderAI21] = &DialectProfile{
		ID:                 domain.ProviderAI21,
		DisplayName:        "AI21 Labs Studio",
		DefaultBaseURL:     "https://api.ai21.com/studio/v1",
		EndpointStrategy:   &adapter.StandardOpenAIEndpointStrategy{DefaultBaseURL: "https://api.ai21.com/studio/v1"},
		AuthStrategy:       &adapter.BearerAuthStrategy{},
		SupportsListModels: false,
		ParamMappings:      standardParamMap,
		DefaultCapabilities: domain.ModelCapabilities{
			Tools:     domain.CapabilitySupported,
			Streaming: domain.CapabilitySupported,
		},
	}

	// 28. Baseten
	r.profiles[domain.ProviderBaseten] = &DialectProfile{
		ID:                 domain.ProviderBaseten,
		DisplayName:        "Baseten Model Gateway",
		DefaultBaseURL:     "https://bridge.baseten.co/v1",
		EndpointStrategy:   &adapter.StandardOpenAIEndpointStrategy{DefaultBaseURL: "https://bridge.baseten.co/v1"},
		AuthStrategy:       &adapter.BearerAuthStrategy{},
		SupportsListModels: false,
		ParamMappings:      standardParamMap,
		DefaultCapabilities: domain.ModelCapabilities{
			Tools:     domain.CapabilitySupported,
			Streaming: domain.CapabilitySupported,
		},
	}

	// 29. NVIDIA NIM
	r.profiles[domain.ProviderNvidia] = &DialectProfile{
		ID:                 domain.ProviderNvidia,
		DisplayName:        "NVIDIA NIM APIs",
		DefaultBaseURL:     "https://integrate.api.nvidia.com/v1",
		EndpointStrategy:   &adapter.StandardOpenAIEndpointStrategy{DefaultBaseURL: "https://integrate.api.nvidia.com/v1"},
		AuthStrategy:       &adapter.BearerAuthStrategy{},
		SupportsListModels: true,
		ParamMappings:      standardParamMap,
		DefaultCapabilities: domain.ModelCapabilities{
			Tools:             domain.CapabilitySupported,
			Streaming:         domain.CapabilitySupported,
			Vision:            domain.CapabilitySupported,
			StructuredOutputs: domain.CapabilitySupported,
		},
	}

	// 30. Scaleway Generative APIs
	r.profiles[domain.ProviderScaleway] = &DialectProfile{
		ID:                 domain.ProviderScaleway,
		DisplayName:        "Scaleway Generative APIs",
		DefaultBaseURL:     "https://api.scaleway.ai/v1",
		EndpointStrategy:   &adapter.StandardOpenAIEndpointStrategy{DefaultBaseURL: "https://api.scaleway.ai/v1"},
		AuthStrategy:       &adapter.BearerAuthStrategy{},
		SupportsListModels: true,
		ParamMappings:      standardParamMap,
		DefaultCapabilities: domain.ModelCapabilities{
			Tools:     domain.CapabilitySupported,
			Streaming: domain.CapabilitySupported,
		},
	}
}
