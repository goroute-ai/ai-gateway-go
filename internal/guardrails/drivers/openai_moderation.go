package drivers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/guardrails"
)

const (
	defaultOpenAIModerationBaseURL = "https://api.openai.com/v1"
	defaultOpenAIModerationModel   = "omni-moderation-latest"
)

// OpenAIModerationDriver evaluates text and image inputs via OpenAI's /v1/moderations API.
type OpenAIModerationDriver struct {
	name               string
	id                 string
	apiKey             string
	endpoint           string
	model              string
	organization       string
	project            string
	action             domain.GuardrailAction
	defaultThreshold   float64
	hasDefaultThresh   bool
	categoryThresholds map[string]float64
	allowedCategories  map[string]struct{}
	httpClient         *http.Client
}

// NewOpenAIModerationDriver constructs an OpenAI Moderation guardrail driver.
func NewOpenAIModerationDriver(cfg guardrails.DriverConfig, httpClient *http.Client) (guardrails.Driver, error) {
	apiKey := resolveSecretOrConfig(cfg, "api_key", "openai_api_key", "token")
	if apiKey == "" {
		return nil, fmt.Errorf("openai_moderation driver requires api_key")
	}

	baseURL := configString(cfg, "base_url", "api_base", "endpoint")
	if baseURL == "" {
		baseURL = defaultOpenAIModerationBaseURL
	}
	endpoint := resolveOpenAIModerationURL(baseURL)

	model := configString(cfg, "model")
	if model == "" {
		model = defaultOpenAIModerationModel
	}

	rawThresholds := configFloatMap(cfg, "category_thresholds", "thresholds", "score_thresholds")
	catThresholds := make(map[string]float64, len(rawThresholds))
	for k, v := range rawThresholds {
		catThresholds[strings.ToLower(strings.TrimSpace(k))] = v
	}

	var allowedCats map[string]struct{}
	if cats := configStringSlice(cfg, "categories"); len(cats) > 0 {
		allowedCats = make(map[string]struct{}, len(cats))
		for _, c := range cats {
			allowedCats[strings.ToLower(strings.TrimSpace(c))] = struct{}{}
		}
	}

	defaultThresh := configFloat(cfg, -1, "threshold", "score_threshold")

	return &OpenAIModerationDriver{
		name:               guardrailName(cfg, ProviderOpenAIModeration),
		id:                 guardrailID(cfg),
		apiKey:             apiKey,
		endpoint:           endpoint,
		model:              model,
		organization:       resolveSecretOrConfig(cfg, "organization", "openai_organization"),
		project:            resolveSecretOrConfig(cfg, "project", "openai_project"),
		action:             effectiveAction(cfg, domain.GuardrailActionBlock),
		defaultThreshold:   defaultThresh,
		hasDefaultThresh:   defaultThresh >= 0,
		categoryThresholds: catThresholds,
		allowedCategories:  allowedCats,
		httpClient:         resolveHTTPClient(httpClient),
	}, nil
}

func resolveOpenAIModerationURL(baseURL string) string {
	trimmed := strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if strings.HasSuffix(trimmed, "/moderations") {
		return trimmed
	}
	if strings.HasSuffix(trimmed, "/v1") {
		return trimmed + "/moderations"
	}
	return trimmed + "/v1/moderations"
}

func (d *OpenAIModerationDriver) Name() string {
	return d.name
}

func (d *OpenAIModerationDriver) SupportedHooks() []domain.GuardrailHook {
	return defaultTextHooks()
}

type openAIModerationRequest struct {
	Model string `json:"model,omitempty"`
	Input any    `json:"input"`
}

type openAIModerationInputItem struct {
	Type     string                    `json:"type"`
	Text     string                    `json:"text,omitempty"`
	ImageURL *openAIModerationImageURL `json:"image_url,omitempty"`
}

type openAIModerationImageURL struct {
	URL string `json:"url"`
}

type openAIModerationResponse struct {
	ID      string                   `json:"id"`
	Model   string                   `json:"model"`
	Results []openAIModerationResult `json:"results"`
}

type openAIModerationResult struct {
	Flagged        bool               `json:"flagged"`
	Categories     map[string]bool    `json:"categories"`
	CategoryScores map[string]float64 `json:"category_scores"`
}

func (d *OpenAIModerationDriver) Evaluate(ctx context.Context, input *domain.GuardrailEvalInput) (*domain.GuardrailEvalResult, error) {
	texts := extractTexts(input)
	var images []domain.ImageURL
	if input != nil {
		images = input.Images
	}
	if !hasNonEmptyText(texts) && len(images) == 0 {
		return &domain.GuardrailEvalResult{
			Decision:          domain.GuardrailDecisionAllow,
			AppliedGuardrails: []string{d.name},
		}, nil
	}

	var payloadInput any
	if len(images) > 0 {
		items := make([]openAIModerationInputItem, 0, len(texts)+len(images))
		for _, t := range texts {
			if strings.TrimSpace(t) != "" {
				items = append(items, openAIModerationInputItem{
					Type: "text",
					Text: t,
				})
			}
		}
		for _, img := range images {
			if strings.TrimSpace(img.URL) != "" {
				items = append(items, openAIModerationInputItem{
					Type:     "image_url",
					ImageURL: &openAIModerationImageURL{URL: img.URL},
				})
			}
		}
		payloadInput = items
	} else {
		nonEmpty := make([]string, 0, len(texts))
		for _, t := range texts {
			if t != "" {
				nonEmpty = append(nonEmpty, t)
			}
		}
		if len(nonEmpty) == 1 {
			payloadInput = nonEmpty[0]
		} else {
			payloadInput = nonEmpty
		}
	}

	headers := map[string]string{
		"Authorization": "Bearer " + d.apiKey,
	}
	if d.organization != "" {
		headers["OpenAI-Organization"] = d.organization
	}
	if d.project != "" {
		headers["OpenAI-Project"] = d.project
	}

	reqPayload := openAIModerationRequest{
		Model: d.model,
		Input: payloadInput,
	}

	status, body, err := doJSONRequest(ctx, d.httpClient, http.MethodPost, d.endpoint, headers, reqPayload, domain.ProviderOpenAI)
	if err != nil {
		return nil, err
	}
	if status < 200 || status >= 300 {
		return nil, fmt.Errorf("openai_moderation returned status %d: %s", status, strings.TrimSpace(string(body)))
	}

	var parsed openAIModerationResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, fmt.Errorf("decode openai_moderation response: %w", err)
	}

	violations := d.collectViolations(parsed.Results)
	if len(violations) == 0 {
		return &domain.GuardrailEvalResult{
			Decision:          domain.GuardrailDecisionAllow,
			AppliedGuardrails: []string{d.name},
			UsageUnits:        1,
		}, nil
	}

	decision := domain.GuardrailDecisionBlock
	if d.action == domain.GuardrailActionAudit {
		decision = domain.GuardrailDecisionFlag
	}
	for i := range violations {
		violations[i].Decision = decision
		violations[i].Action = d.action
	}

	return &domain.GuardrailEvalResult{
		Decision:          decision,
		Violations:        violations,
		AppliedGuardrails: []string{d.name},
		UsageUnits:        1,
		ErrorMessage:      violations[0].Message,
	}, nil
}

func (d *OpenAIModerationDriver) collectViolations(results []openAIModerationResult) []domain.GuardrailViolation {
	var violations []domain.GuardrailViolation
	for _, res := range results {
		catSet := make(map[string]struct{}, len(res.Categories)+len(res.CategoryScores))
		for k := range res.Categories {
			catSet[strings.ToLower(k)] = struct{}{}
		}
		for k := range res.CategoryScores {
			catSet[strings.ToLower(k)] = struct{}{}
		}
		cats := make([]string, 0, len(catSet))
		for k := range catSet {
			cats = append(cats, k)
		}
		sort.Strings(cats)

		matchedAny := false
		for _, cat := range cats {
			if len(d.allowedCategories) > 0 {
				if _, ok := d.allowedCategories[cat]; !ok {
					continue
				}
			}
			score, hasScore := lookupScoreCaseInsensitive(res.CategoryScores, cat)
			flagged := lookupFlagCaseInsensitive(res.Categories, cat)

			triggered := false
			if thresh, hasCustom := d.categoryThresholds[cat]; hasCustom {
				triggered = hasScore && score >= thresh
			} else if d.hasDefaultThresh {
				triggered = hasScore && score >= d.defaultThreshold
			} else {
				triggered = flagged
			}

			if triggered {
				matchedAny = true
				var scorePtr *float64
				if hasScore {
					s := score
					scorePtr = &s
				}
				violations = append(violations, domain.GuardrailViolation{
					GuardrailName: d.name,
					GuardrailID:   d.id,
					Provider:      ProviderOpenAIModeration,
					Category:      cat,
					Rule:          cat,
					Message:       fmt.Sprintf("OpenAI moderation flagged category %q", cat),
					Score:         scorePtr,
				})
			}
		}

		// If OpenAI flagged the input overall without custom thresholds and no per-category bool was true.
		if !matchedAny && res.Flagged && len(d.categoryThresholds) == 0 && !d.hasDefaultThresh && len(d.allowedCategories) == 0 {
			violations = append(violations, domain.GuardrailViolation{
				GuardrailName: d.name,
				GuardrailID:   d.id,
				Provider:      ProviderOpenAIModeration,
				Category:      "moderation",
				Rule:          "flagged",
				Message:       "OpenAI moderation flagged content",
			})
		}
	}
	return violations
}

func lookupScoreCaseInsensitive(m map[string]float64, key string) (float64, bool) {
	if v, ok := m[key]; ok {
		return v, true
	}
	for k, v := range m {
		if strings.EqualFold(k, key) {
			return v, true
		}
	}
	return 0, false
}

func lookupFlagCaseInsensitive(m map[string]bool, key string) bool {
	if v, ok := m[key]; ok {
		return v
	}
	for k, v := range m {
		if strings.EqualFold(k, key) {
			return v
		}
	}
	return false
}
