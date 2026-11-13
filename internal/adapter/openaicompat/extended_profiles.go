package openaicompat

import (
	"github.com/goroute-ai/ai-gateway-go/internal/adapter"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
)

func boolPtr(v bool) *bool { return &v }

type extendedProfileSpec struct {
	id                         domain.ProviderType
	displayName                string
	baseURL                    string
	supportsListModels         bool
	supportsStreamOptions      *bool
	extractReasoningDelta      bool
	reasoningMapping           string
	dropUnsupportedParams      bool
	convertContentListToString bool
	strippedParams             []string
	authHeader                 string
	defaultHeaders             map[string]string
	ops                        *ProviderOperations
	caps                       domain.ModelCapabilities
}

// registerExtendedProfiles tunes existing profiles (stream_options, reasoning mappings,
// operation support) and registers additional certified OpenAI-compatible providers.
func (r *ProfileRegistry) registerExtendedProfiles() {
	// Tune existing profiles with explicit stream_options, reasoning mappings, and operation support
	if p, ok := r.profiles[domain.ProviderPerplexity]; ok {
		p.SupportsStreamOptions = boolPtr(false)
		p.DropUnsupportedParams = true
		p.StrippedParams = []string{"tools", "tool_choice", "parallel_tool_calls", "logit_bias", "logprobs", "top_logprobs", "service_tier"}
		p.SupportedOperations = &ProviderOperations{Chat: true}
	}
	if p, ok := r.profiles[domain.ProviderCloudflare]; ok {
		p.SupportsStreamOptions = boolPtr(false)
	}
	if p, ok := r.profiles[domain.ProviderReplicate]; ok {
		p.SupportsStreamOptions = boolPtr(false)
	}
	if p, ok := r.profiles[domain.ProviderOpenRouter]; ok {
		p.ReasoningMapping = "openrouter_reasoning"
		p.DropUnsupportedParams = true
		p.DefaultHeaders = map[string]string{
			"HTTP-Referer": "https://github.com/goroute-ai/ai-gateway-go",
			"X-Title":      "GoRoute AI Gateway",
		}
	}
	if p, ok := r.profiles[domain.ProviderDashScope]; ok {
		p.ReasoningMapping = "dashscope_thinking"
		p.DropUnsupportedParams = true
	}
	if p, ok := r.profiles[domain.ProviderVolcengine]; ok {
		p.ReasoningMapping = "thinking_enabled"
		p.DropUnsupportedParams = true
		p.StrippedParams = []string{"service_tier", "logit_bias"}
	}
	if p, ok := r.profiles[domain.ProviderMoonshot]; ok {
		p.ReasoningMapping = "thinking_enabled"
		p.DropUnsupportedParams = true
	}
	if p, ok := r.profiles[domain.ProviderNvidia]; ok {
		p.ReasoningMapping = "chat_template_thinking"
		p.DropUnsupportedParams = true
	}
	for _, pid := range []domain.ProviderType{
		domain.ProviderMiniMax, domain.ProviderXAI, domain.ProviderCerebras,
		domain.ProviderSambaNova, domain.ProviderNovita, domain.ProviderNebius,
		domain.ProviderHyperbolic, domain.ProviderSiliconFlow,
	} {
		if p, ok := r.profiles[pid]; ok {
			p.DropUnsupportedParams = true
		}
	}
	if p, ok := r.profiles[domain.ProviderVoyage]; ok {
		p.SupportedOperations = &ProviderOperations{Embeddings: true, Rerank: true}
	}
	if p, ok := r.profiles[domain.ProviderJina]; ok {
		p.SupportedOperations = &ProviderOperations{Rerank: true}
	}

	// Completion is a distinct upstream endpoint. Enable it only for profiles
	// whose provider endpoint inventory explicitly declares text completions.
	for _, pid := range []domain.ProviderType{
		domain.ProviderAI21, domain.ProviderAzure, domain.ProviderBaseten,
		domain.ProviderCerebras, domain.ProviderCloudflare, domain.ProviderDatabricks,
		domain.ProviderDeepInfra, domain.ProviderDeepSeek, domain.ProviderFireworks,
		domain.ProviderFriendli, domain.ProviderGroq, domain.ProviderHyperbolic,
		domain.ProviderLambda, domain.ProviderMistral, domain.ProviderMoonshot,
		domain.ProviderNebius, domain.ProviderNovita, domain.ProviderPerplexity,
		domain.ProviderReplicate, domain.ProviderSambaNova, domain.ProviderScaleway,
		domain.ProviderSnowflake, domain.ProviderTogether, domain.ProviderVolcengine,
		domain.ProviderXAI, domain.ProviderMiniMax, domain.ProviderLlamaGate,
		domain.ProviderXiaomiMiMo, domain.ProviderSarvam, domain.ProviderAnyscale,
		domain.ProviderBigModel, domain.ProviderVercelAIGateway, domain.ProviderAIHubMix,
		domain.ProviderFeatherless, domain.ProviderFal, domain.ProviderZAI,
		domain.ProviderGMI, domain.ProviderCrusoe, domain.ProviderUpstage,
		domain.ProviderOVHCloud, domain.ProviderWandB, domain.ProviderNscale,
		domain.ProviderSynthetic, domain.ProviderNanoGPT, domain.ProviderYi,
		domain.ProviderBaichuan, domain.ProviderStepFun, domain.ProviderLMStudio,
		domain.ProviderLlamafile, domain.ProviderXinference,
	} {
		if p, ok := r.profiles[pid]; ok {
			if p.SupportedOperations == nil {
				p.SupportedOperations = &ProviderOperations{
					Chat:       true,
					Embeddings: p.DefaultCapabilities.Embeddings == domain.CapabilitySupported,
				}
			}
			p.SupportedOperations.Completion = true
		}
	}

	// These profiles expose operation-specific OpenAI-compatible endpoints in
	// upstream provider endpoint inventories and use the matching wire shape.
	setOps := func(pid domain.ProviderType, update func(*ProviderOperations)) {
		if p, ok := r.profiles[pid]; ok {
			if p.SupportedOperations == nil {
				p.SupportedOperations = &ProviderOperations{
					Chat:       true,
					Embeddings: p.DefaultCapabilities.Embeddings == domain.CapabilitySupported,
				}
			}
			update(p.SupportedOperations)
		}
	}
	setOps(domain.ProviderTogether, func(o *ProviderOperations) { o.Rerank = true })
	setOps(domain.ProviderFireworks, func(o *ProviderOperations) {
		o.Rerank = true
		o.ImageGen = true
		o.AudioSTT = true
	})
	setOps(domain.ProviderNovita, func(o *ProviderOperations) { o.Rerank = true })
	setOps(domain.ProviderNvidia, func(o *ProviderOperations) { o.Rerank = true })
	setOps(domain.ProviderGroq, func(o *ProviderOperations) {
		o.AudioSTT = true
		o.AudioTTS = true
	})
	setOps(domain.ProviderXAI, func(o *ProviderOperations) {
		o.ImageGen = true
		o.AudioSTT = true
	})
	setOps(domain.ProviderCloudflare, func(o *ProviderOperations) { o.AudioSTT = true })

	stdChatCaps := domain.ModelCapabilities{
		Tools:             domain.CapabilitySupported,
		Streaming:         domain.CapabilitySupported,
		StructuredOutputs: domain.CapabilitySupported,
	}
	stdReasoningCaps := domain.ModelCapabilities{
		Tools:             domain.CapabilitySupported,
		Streaming:         domain.CapabilitySupported,
		StructuredOutputs: domain.CapabilitySupported,
		Reasoning:         domain.CapabilitySupported,
	}
	chatOps := &ProviderOperations{Chat: true, Embeddings: true}
	chatOnlyOps := &ProviderOperations{Chat: true}
	falOps := &ProviderOperations{Chat: true, ImageGen: true, ImageEdit: true}

	specs := []extendedProfileSpec{
		{id: domain.ProviderGitHubCopilot, displayName: "GitHub Copilot", baseURL: "https://api.githubcopilot.com", supportsListModels: true, ops: chatOnlyOps, caps: stdReasoningCaps},
		{id: domain.ProviderVercelAIGateway, displayName: "Vercel AI Gateway", baseURL: "https://ai-gateway.vercel.sh/v1", supportsListModels: true, ops: chatOps, caps: stdReasoningCaps},
		{id: domain.ProviderHuggingFace, displayName: "Hugging Face Inference", baseURL: "https://router.huggingface.co/v1", supportsListModels: false, ops: chatOps, caps: stdChatCaps},
		{id: domain.ProviderFeatherless, displayName: "Featherless AI", baseURL: "https://api.featherless.ai/v1", supportsListModels: true, ops: chatOnlyOps, caps: stdChatCaps},
		{id: domain.ProviderFal, displayName: "fal.ai", baseURL: "https://fal.run/openrouter/router/openai/v1", supportsListModels: false, ops: falOps, caps: stdChatCaps},
		{id: domain.ProviderZAI, displayName: "Z.ai", baseURL: "https://api.z.ai/api/paas/v4", supportsListModels: false, extractReasoningDelta: true, reasoningMapping: "thinking_enabled", dropUnsupportedParams: true, ops: chatOnlyOps, caps: stdReasoningCaps},
		{id: domain.ProviderPoe, displayName: "Poe", baseURL: "https://api.poe.com/v1", supportsListModels: true, ops: chatOnlyOps, caps: stdChatCaps},
		{id: domain.ProviderHelicone, displayName: "Helicone AI Gateway", baseURL: "https://ai-gateway.helicone.ai/v1", supportsListModels: true, ops: chatOnlyOps, caps: stdChatCaps},
		{id: domain.ProviderAIHubMix, displayName: "AIHubMix", baseURL: "https://aihubmix.com/v1", supportsListModels: true, ops: chatOps, caps: stdReasoningCaps},
		{id: domain.ProviderVenice, displayName: "Venice AI", baseURL: "https://api.venice.ai/api/v1", supportsListModels: true, ops: chatOnlyOps, caps: stdChatCaps},
		{id: domain.ProviderChutes, displayName: "Chutes AI", baseURL: "https://llm.chutes.ai/v1", supportsListModels: true, extractReasoningDelta: true, ops: chatOnlyOps, caps: stdReasoningCaps},
		{id: domain.ProviderGMI, displayName: "GMI Cloud", baseURL: "https://api.gmi-serving.com/v1", supportsListModels: true, ops: chatOnlyOps, caps: stdChatCaps},
		{id: domain.ProviderLlamaGate, displayName: "LlamaGate", baseURL: "https://api.llamagate.dev/v1", supportsListModels: true, ops: chatOnlyOps, caps: stdChatCaps},
		{id: domain.ProviderSarvam, displayName: "Sarvam AI", baseURL: "https://api.sarvam.ai/v1", supportsListModels: false, authHeader: "api-subscription-key", ops: chatOnlyOps, caps: stdChatCaps},
		{id: domain.ProviderCrusoe, displayName: "Crusoe Cloud", baseURL: "https://managed-inference.crusoecloud.com/v1", supportsListModels: true, ops: chatOnlyOps, caps: stdChatCaps},
		{id: domain.ProviderParasail, displayName: "Parasail", baseURL: "https://api.parasail.io/v1", supportsListModels: true, ops: chatOnlyOps, caps: stdChatCaps},
		{id: domain.ProviderUpstage, displayName: "Upstage Solar", baseURL: "https://api.upstage.ai/v1/solar", supportsListModels: false, ops: chatOps, caps: stdChatCaps},
		{id: domain.ProviderOVHCloud, displayName: "OVHcloud AI Endpoints", baseURL: "https://oai.endpoints.kepler.ai.cloud.ovh.net/v1", supportsListModels: true, ops: chatOps, caps: stdChatCaps},
		{id: domain.ProviderWandB, displayName: "W&B Inference", baseURL: "https://api.inference.wandb.ai/v1", supportsListModels: true, ops: chatOnlyOps, caps: stdReasoningCaps},
		{id: domain.ProviderNscale, displayName: "Nscale", baseURL: "https://inference.api.nscale.com/v1", supportsListModels: true, ops: chatOnlyOps, caps: stdChatCaps},
		{id: domain.ProviderPublicAI, displayName: "Public AI", baseURL: "https://api.publicai.co/v1", supportsListModels: true, convertContentListToString: true, ops: chatOnlyOps, caps: stdChatCaps},
		{id: domain.ProviderSynthetic, displayName: "Synthetic", baseURL: "https://api.synthetic.new/openai/v1", supportsListModels: true, extractReasoningDelta: true, ops: chatOnlyOps, caps: stdReasoningCaps},
		{id: domain.ProviderNanoGPT, displayName: "NanoGPT", baseURL: "https://nano-gpt.com/api/v1", supportsListModels: true, extractReasoningDelta: true, ops: chatOnlyOps, caps: stdReasoningCaps},
		{id: domain.ProviderXiaomiMiMo, displayName: "Xiaomi MiMo", baseURL: "https://api.xiaomimimo.com/v1", supportsListModels: false, ops: chatOnlyOps, caps: stdReasoningCaps},
		{id: domain.ProviderReka, displayName: "Reka AI", baseURL: "https://api.reka.ai/v1", supportsListModels: false, ops: chatOnlyOps, caps: stdChatCaps},
		{id: domain.ProviderYi, displayName: "01.AI (Yi)", baseURL: "https://api.lingyiwanwu.com/v1", supportsListModels: true, ops: chatOnlyOps, caps: stdChatCaps},
		{id: domain.ProviderBaichuan, displayName: "Baichuan AI", baseURL: "https://api.baichuan-ai.com/v1", supportsListModels: false, ops: chatOnlyOps, caps: stdChatCaps},
		{id: domain.ProviderStepFun, displayName: "StepFun", baseURL: "https://api.stepfun.com/v1", supportsListModels: true, ops: chatOnlyOps, caps: stdChatCaps},
		{id: domain.ProviderLMStudio, displayName: "LM Studio (Local)", baseURL: "http://localhost:1234/v1", supportsListModels: true, extractReasoningDelta: true, ops: chatOps, caps: stdReasoningCaps},
		{id: domain.ProviderLlamafile, displayName: "llamafile (Local)", baseURL: "http://localhost:8080/v1", supportsListModels: true, ops: chatOps, caps: stdChatCaps},
		{id: domain.ProviderXinference, displayName: "Xorbits Inference", baseURL: "http://localhost:9997/v1", supportsListModels: true, ops: chatOps, caps: stdChatCaps},
	}

	for _, s := range specs {
		var authStrategy adapter.AuthStrategy = &adapter.BearerAuthStrategy{}
		if s.authHeader != "" {
			authStrategy = &adapter.HeaderAuthStrategy{HeaderName: s.authHeader}
		}
		r.profiles[s.id] = &DialectProfile{
			ID:                         s.id,
			DisplayName:                s.displayName,
			DefaultBaseURL:             s.baseURL,
			EndpointStrategy:           &adapter.StandardOpenAIEndpointStrategy{DefaultBaseURL: s.baseURL},
			AuthStrategy:               authStrategy,
			DefaultHeaders:             s.defaultHeaders,
			SupportsListModels:         s.supportsListModels,
			SupportsStreamOptions:      s.supportsStreamOptions,
			DropUnsupportedParams:      s.dropUnsupportedParams,
			StrippedParams:             s.strippedParams,
			ReasoningMapping:           s.reasoningMapping,
			SupportedOperations:        s.ops,
			ExtractReasoningDelta:      s.extractReasoningDelta,
			ConvertContentListToString: s.convertContentListToString,
			ParamMappings:              map[string]string{"max_completion_tokens": "max_tokens"},
			DefaultCapabilities:        s.caps,
		}
	}
}
