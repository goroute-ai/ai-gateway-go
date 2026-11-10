package domain

// CapabilityState represents the verification level of a model capability.
// It uses an explicit tri-state to distinguish known support, verified lack of support,
// and unverified features.
type CapabilityState string

const (
	CapabilityUnknown     CapabilityState = "unknown"
	CapabilitySupported   CapabilityState = "supported"
	CapabilityUnsupported CapabilityState = "unsupported"
)

// ModelCapabilities captures the tri-state capability verification for an LLM.
type ModelCapabilities struct {
	Tools             CapabilityState `json:"tools"`
	Streaming         CapabilityState `json:"streaming"`
	Vision            CapabilityState `json:"vision"`
	Reasoning         CapabilityState `json:"reasoning"`
	StructuredOutputs CapabilityState `json:"structured_outputs"`
	Embeddings        CapabilityState `json:"embeddings"`
	Rerank            CapabilityState `json:"rerank"`
	Moderation        CapabilityState `json:"moderation"`
	ImageGen          CapabilityState `json:"image_gen"`
	AudioSTT          CapabilityState `json:"audio_stt"`
	AudioTTS          CapabilityState `json:"audio_tts"`
	Batches           CapabilityState `json:"batches"`
	Realtime          CapabilityState `json:"realtime"`
}

// PricingStatus defines the provenance and verification status of a model's token pricing.
type PricingStatus string

const (
	PricingStatusVerified   PricingStatus = "verified"
	PricingStatusUnknown    PricingStatus = "unknown"
	PricingStatusCustom     PricingStatus = "custom"
	PricingStatusUnrecorded PricingStatus = "unrecorded"
)

// ResolvePricingStatus defensively determines the pricing status of a model.
// If explicitly set on the GlobalModel, that status is preserved.
// If the status is empty, it returns PricingStatusUnknown to guarantee fail-closed budget safety.
func ResolvePricingStatus(gm *GlobalModel) PricingStatus {
	if gm == nil {
		return PricingStatusUnknown
	}
	switch gm.PricingStatus {
	case PricingStatusVerified, PricingStatusCustom, PricingStatusUnknown, PricingStatusUnrecorded:
		return gm.PricingStatus
	}
	return PricingStatusUnknown
}
