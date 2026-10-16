package ratelimit

import (
	"encoding/json"
	"strings"
	"unicode"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
)

// TokenizerProfile identifies the model-family BPE/SentencePiece tokenization profile.
type TokenizerProfile string

const (
	ProfileO200K         TokenizerProfile = "o200k_base"     // GPT-4o, GPT-4.1, o1, o3, o4
	ProfileCL100K        TokenizerProfile = "cl100k_base"    // GPT-4, GPT-3.5, text-embedding-3
	ProfileClaudeBPE     TokenizerProfile = "claude_bpe"     // Anthropic Claude 3.x / 4.x
	ProfileGeminiSP      TokenizerProfile = "gemini_sp"      // Google Gemini SentencePiece
	ProfileMistralTekken TokenizerProfile = "mistral_tekken" // Mistral Tekken / Llama 3 BPE
)

// ResolveTokenizerProfile selects the appropriate subword tokenization profile for a model.
func ResolveTokenizerProfile(model string) TokenizerProfile {
	m := strings.ToLower(strings.TrimSpace(model))
	switch {
	case strings.Contains(m, "claude") || strings.HasPrefix(m, "anthropic/"):
		return ProfileClaudeBPE
	case strings.Contains(m, "gemini") || strings.Contains(m, "gemma"):
		return ProfileGeminiSP
	case strings.Contains(m, "mistral") || strings.Contains(m, "llama"):
		return ProfileMistralTekken
	case strings.Contains(m, "gpt-3.5") || strings.Contains(m, "embedding"):
		return ProfileCL100K
	default:
		return ProfileO200K
	}
}

// EstimateTextTokens estimates BPE/SentencePiece subword tokens for a text segment using the target TokenizerProfile.
// Splits alphanumeric words, code/JSON punctuation symbols, and UTF-8 multi-byte sequences.
func EstimateTextTokens(text string, profile TokenizerProfile) int {
	if len(text) == 0 {
		return 0
	}

	// Subword length divisor (hundredths of characters per token, e.g. 380 = 3.8 chars/token)
	charsPerTokenX100 := 400
	switch profile {
	case ProfileClaudeBPE:
		charsPerTokenX100 = 360 // Claude BPE is slightly denser on prose/code (~3.6 chars/token)
	case ProfileGeminiSP:
		charsPerTokenX100 = 410 // Gemini SentencePiece averages ~4.1 chars/token
	case ProfileMistralTekken:
		charsPerTokenX100 = 380
	case ProfileCL100K:
		charsPerTokenX100 = 390
	case ProfileO200K:
		charsPerTokenX100 = 420 // o200k_base has a 200k vocabulary (~4.2 chars/token)
	}

	alnumChars := 0
	punctTokens := 0
	nonASCIIBytes := 0

	for _, r := range text {
		if r > 127 {
			nonASCIIBytes += len(string(r))
		} else if unicode.IsLetter(r) || unicode.IsDigit(r) {
			alnumChars++
		} else if !unicode.IsSpace(r) {
			// Code/JSON punctuation symbols ({, }, :, ", [, ], (, )) often form dedicated BPE tokens
			punctTokens++
		}
	}

	wordSubwords := (alnumChars*100 + charsPerTokenX100 - 1) / charsPerTokenX100
	punctSubwords := (punctTokens + 1) / 2
	utf8Subwords := (nonASCIIBytes + 1) / 2

	total := wordSubwords + punctSubwords + utf8Subwords
	if total < 1 {
		total = 1
	}
	return total
}

// EstimateRequestTokens computes a model-aware pre-flight token estimate for a chat completion request.
// Treated explicitly as a pre-flight admission estimate and reconciled against exact provider usage post-flight.
func EstimateRequestTokens(req *domain.CanonicalChatRequest) int {
	if req == nil {
		return 16
	}
	profile := ResolveTokenizerProfile(req.Model)
	totalTokens := 3 // assistant reply priming

	msgFraming := 4
	if profile == ProfileClaudeBPE {
		msgFraming = 5
	} else if profile == ProfileGeminiSP {
		msgFraming = 3
	}

	for _, m := range req.Messages {
		totalTokens += msgFraming
		totalTokens += EstimateTextTokens(m.Content, profile)
		totalTokens += EstimateTextTokens(m.Name, profile)
		totalTokens += EstimateTextTokens(m.ReasoningContent, profile)
		for _, p := range m.Parts {
			totalTokens += EstimateTextTokens(p.Text, profile)
			if p.ImageURL != nil {
				if strings.EqualFold(p.ImageURL.Detail, "high") {
					totalTokens += 765
				} else {
					totalTokens += 255
				}
			}
		}
		for _, tc := range m.ToolCalls {
			totalTokens += 4 + EstimateTextTokens(tc.Function.Name, profile) + EstimateTextTokens(tc.Function.Arguments, profile)
		}
	}

	for _, t := range req.Tools {
		totalTokens += 8 + EstimateTextTokens(t.Function.Name, profile) + EstimateTextTokens(t.Function.Description, profile)
		if len(t.Function.Parameters) > 0 {
			if b, err := json.Marshal(t.Function.Parameters); err == nil {
				totalTokens += EstimateTextTokens(string(b), profile)
			}
		}
	}

	if totalTokens < 1 {
		totalTokens = 1
	}
	return totalTokens
}
