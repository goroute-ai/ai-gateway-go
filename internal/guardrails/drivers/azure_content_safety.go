package drivers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/guardrails"
)

const (
	defaultAzureContentSafetyAPIVersion = "2024-09-01"
	defaultAzureSeverityThreshold       = 2
)

type azureAuth struct {
	apiKey      string
	bearerToken string
}

func resolveAzureAuth(cfg guardrails.DriverConfig) (azureAuth, error) {
	apiKey := resolveSecretOrConfig(cfg, "api_key", "azure_api_key", "subscription_key")
	bearer := resolveSecretOrConfig(cfg, "bearer_token", "aad_token", "token")
	if apiKey == "" && bearer == "" {
		return azureAuth{}, fmt.Errorf("azure content safety driver requires api_key or bearer_token")
	}
	return azureAuth{apiKey: apiKey, bearerToken: bearer}, nil
}

func (a azureAuth) headers() map[string]string {
	h := make(map[string]string, 2)
	if a.apiKey != "" {
		h["Ocp-Apim-Subscription-Key"] = a.apiKey
	}
	if a.bearerToken != "" {
		h["Authorization"] = "Bearer " + a.bearerToken
	}
	return h
}

func buildAzureEndpoint(baseURL, path, apiVersion string) string {
	trimmed := strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if apiVersion == "" {
		apiVersion = defaultAzureContentSafetyAPIVersion
	}
	return fmt.Sprintf("%s%s?api-version=%s", trimmed, path, url.QueryEscape(apiVersion))
}

// AzurePromptShieldDriver evaluates user prompts and retrieved documents for direct and
// indirect prompt injection attacks using Azure AI Content Safety Prompt Shields.
type AzurePromptShieldDriver struct {
	name       string
	id         string
	endpoint   string
	auth       azureAuth
	action     domain.GuardrailAction
	httpClient *http.Client
}

// NewAzurePromptShieldDriver constructs an Azure AI Content Safety Prompt Shields driver.
func NewAzurePromptShieldDriver(cfg guardrails.DriverConfig, httpClient *http.Client) (guardrails.Driver, error) {
	baseURL := configString(cfg, "api_base", "base_url", "endpoint")
	if baseURL == "" {
		return nil, fmt.Errorf("azure/prompt_shield driver requires api_base or endpoint")
	}
	auth, err := resolveAzureAuth(cfg)
	if err != nil {
		return nil, fmt.Errorf("azure/prompt_shield: %w", err)
	}
	apiVersion := configString(cfg, "api_version")
	return &AzurePromptShieldDriver{
		name:       guardrailName(cfg, ProviderAzurePromptShield),
		id:         guardrailID(cfg),
		endpoint:   buildAzureEndpoint(baseURL, "/contentsafety/text:shieldPrompt", apiVersion),
		auth:       auth,
		action:     effectiveAction(cfg, domain.GuardrailActionBlock),
		httpClient: resolveHTTPClient(httpClient),
	}, nil
}

func (d *AzurePromptShieldDriver) Name() string {
	return d.name
}

func (d *AzurePromptShieldDriver) SupportedHooks() []domain.GuardrailHook {
	return []domain.GuardrailHook{
		domain.GuardrailHookPreCall,
		domain.GuardrailHookDuringCall,
		domain.GuardrailHookLoggingOnly,
	}
}

type azurePromptShieldRequest struct {
	UserPrompt string   `json:"userPrompt,omitempty"`
	Documents  []string `json:"documents,omitempty"`
}

type azurePromptShieldResponse struct {
	UserPromptAnalysis *struct {
		AttackDetected bool `json:"attackDetected"`
	} `json:"userPromptAnalysis"`
	DocumentsAnalysis []struct {
		AttackDetected bool `json:"attackDetected"`
	} `json:"documentsAnalysis"`
}

func (d *AzurePromptShieldDriver) Evaluate(ctx context.Context, input *domain.GuardrailEvalInput) (*domain.GuardrailEvalResult, error) {
	userPrompt, documents := extractAzurePromptShieldInputs(input)
	if strings.TrimSpace(userPrompt) == "" && len(documents) == 0 {
		return &domain.GuardrailEvalResult{
			Decision:          domain.GuardrailDecisionAllow,
			AppliedGuardrails: []string{d.name},
		}, nil
	}

	reqPayload := azurePromptShieldRequest{
		UserPrompt: userPrompt,
		Documents:  documents,
	}

	status, body, err := doJSONRequest(ctx, d.httpClient, http.MethodPost, d.endpoint, d.auth.headers(), reqPayload, domain.ProviderAzure)
	if err != nil {
		return nil, err
	}
	if status < 200 || status >= 300 {
		return nil, fmt.Errorf("azure/prompt_shield returned status %d: %s", status, strings.TrimSpace(string(body)))
	}

	var parsed azurePromptShieldResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, fmt.Errorf("decode azure/prompt_shield response: %w", err)
	}

	var violations []domain.GuardrailViolation
	if parsed.UserPromptAnalysis != nil && parsed.UserPromptAnalysis.AttackDetected {
		violations = append(violations, domain.GuardrailViolation{
			GuardrailName: d.name,
			GuardrailID:   d.id,
			Provider:      ProviderAzurePromptShield,
			Category:      "prompt_shield",
			Rule:          "user_prompt_attack",
			Message:       "Azure Prompt Shield detected a jailbreak or prompt attack in userPrompt",
		})
	}
	for i, docRes := range parsed.DocumentsAnalysis {
		if docRes.AttackDetected {
			violations = append(violations, domain.GuardrailViolation{
				GuardrailName: d.name,
				GuardrailID:   d.id,
				Provider:      ProviderAzurePromptShield,
				Category:      "prompt_shield",
				Rule:          fmt.Sprintf("document_attack_%d", i),
				Message:       fmt.Sprintf("Azure Prompt Shield detected an indirect attack in document[%d]", i),
			})
		}
	}

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

func extractAzurePromptShieldInputs(input *domain.GuardrailEvalInput) (string, []string) {
	if input == nil {
		return "", nil
	}
	var documents []string
	if input.Metadata != nil {
		if rawDocs, ok := input.Metadata["documents"]; ok {
			documents = append(documents, stringSliceFromAny(rawDocs)...)
		}
	}

	var userParts []string
	for _, msg := range input.StructuredMessages {
		txt := msg.Content
		if txt == "" {
			var sb strings.Builder
			for _, p := range msg.Parts {
				if p.Type == "text" {
					sb.WriteString(p.Text)
				}
			}
			txt = sb.String()
		}
		if strings.TrimSpace(txt) == "" {
			continue
		}
		if strings.EqualFold(msg.Role, "tool") {
			documents = append(documents, txt)
		} else if strings.EqualFold(msg.Role, "user") {
			userParts = append(userParts, txt)
		}
	}

	userPrompt := strings.Join(userParts, "\n")
	if strings.TrimSpace(userPrompt) == "" {
		userPrompt = joinedNonEmptyText(extractTexts(input))
	}
	return userPrompt, documents
}

// AzureTextModerationsDriver evaluates text content against Azure AI Content Safety
// Text Analyze categories (Hate, SelfHarm, Sexual, Violence) with configurable severity thresholds (0-7).
type AzureTextModerationsDriver struct {
	name               string
	id                 string
	endpoint           string
	auth               azureAuth
	action             domain.GuardrailAction
	categories         []string
	blocklistNames     []string
	haltOnBlocklistHit bool
	outputType         string
	defaultThreshold   int
	categoryThresholds map[string]int
	httpClient         *http.Client
}

// NewAzureTextModerationsDriver constructs an Azure AI Content Safety Text Analyze driver.
func NewAzureTextModerationsDriver(cfg guardrails.DriverConfig, httpClient *http.Client) (guardrails.Driver, error) {
	baseURL := configString(cfg, "api_base", "base_url", "endpoint")
	if baseURL == "" {
		return nil, fmt.Errorf("azure/text_moderations driver requires api_base or endpoint")
	}
	auth, err := resolveAzureAuth(cfg)
	if err != nil {
		return nil, fmt.Errorf("azure/text_moderations: %w", err)
	}
	apiVersion := configString(cfg, "api_version")

	categories := configStringSlice(cfg, "categories")
	if len(categories) == 0 {
		categories = []string{"Hate", "SelfHarm", "Sexual", "Violence"}
	}

	outputType := configString(cfg, "output_type")
	if outputType == "" {
		outputType = "EightSeverityLevels"
	}

	rawThresholds := configIntMap(cfg, "severity_thresholds", "category_thresholds", "thresholds")
	catThresholds := make(map[string]int, len(rawThresholds))
	for k, v := range rawThresholds {
		catThresholds[strings.ToLower(strings.TrimSpace(k))] = v
	}

	defaultThresh := configInt(cfg, defaultAzureSeverityThreshold, "severity_threshold", "threshold")
	if defaultThresh < 0 {
		defaultThresh = 0
	}
	if defaultThresh > 7 {
		defaultThresh = 7
	}

	return &AzureTextModerationsDriver{
		name:               guardrailName(cfg, ProviderAzureTextModerations),
		id:                 guardrailID(cfg),
		endpoint:           buildAzureEndpoint(baseURL, "/contentsafety/text:analyze", apiVersion),
		auth:               auth,
		action:             effectiveAction(cfg, domain.GuardrailActionBlock),
		categories:         categories,
		blocklistNames:     configStringSlice(cfg, "blocklist_names"),
		haltOnBlocklistHit: configBool(cfg, false, "halt_on_blocklist_hit"),
		outputType:         outputType,
		defaultThreshold:   defaultThresh,
		categoryThresholds: catThresholds,
		httpClient:         resolveHTTPClient(httpClient),
	}, nil
}

func (d *AzureTextModerationsDriver) Name() string {
	return d.name
}

func (d *AzureTextModerationsDriver) SupportedHooks() []domain.GuardrailHook {
	return defaultTextHooks()
}

type azureTextAnalyzeRequest struct {
	Text               string   `json:"text"`
	Categories         []string `json:"categories,omitempty"`
	BlocklistNames     []string `json:"blocklistNames,omitempty"`
	HaltOnBlocklistHit bool     `json:"haltOnBlocklistHit,omitempty"`
	OutputType         string   `json:"outputType,omitempty"`
}

type azureTextAnalyzeResponse struct {
	BlocklistsMatch []struct {
		BlocklistName     string `json:"blocklistName"`
		BlocklistItemID   string `json:"blocklistItemId"`
		BlocklistItemText string `json:"blocklistItemText"`
	} `json:"blocklistsMatch"`
	CategoriesAnalysis []struct {
		Category string `json:"category"`
		Severity int    `json:"severity"`
	} `json:"categoriesAnalysis"`
}

func (d *AzureTextModerationsDriver) Evaluate(ctx context.Context, input *domain.GuardrailEvalInput) (*domain.GuardrailEvalResult, error) {
	text := joinedNonEmptyText(extractTexts(input))
	if strings.TrimSpace(text) == "" {
		return &domain.GuardrailEvalResult{
			Decision:          domain.GuardrailDecisionAllow,
			AppliedGuardrails: []string{d.name},
		}, nil
	}

	reqPayload := azureTextAnalyzeRequest{
		Text:               text,
		Categories:         d.categories,
		BlocklistNames:     d.blocklistNames,
		HaltOnBlocklistHit: d.haltOnBlocklistHit,
		OutputType:         d.outputType,
	}

	status, body, err := doJSONRequest(ctx, d.httpClient, http.MethodPost, d.endpoint, d.auth.headers(), reqPayload, domain.ProviderAzure)
	if err != nil {
		return nil, err
	}
	if status < 200 || status >= 300 {
		return nil, fmt.Errorf("azure/text_moderations returned status %d: %s", status, strings.TrimSpace(string(body)))
	}

	var parsed azureTextAnalyzeResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, fmt.Errorf("decode azure/text_moderations response: %w", err)
	}

	var violations []domain.GuardrailViolation
	for _, cat := range parsed.CategoriesAnalysis {
		thresh := d.defaultThreshold
		if custom, ok := d.categoryThresholds[strings.ToLower(strings.TrimSpace(cat.Category))]; ok {
			thresh = custom
		}
		if cat.Severity >= thresh {
			score := float64(cat.Severity)
			violations = append(violations, domain.GuardrailViolation{
				GuardrailName: d.name,
				GuardrailID:   d.id,
				Provider:      ProviderAzureTextModerations,
				Category:      cat.Category,
				Rule:          cat.Category,
				Severity:      fmt.Sprintf("%d", cat.Severity),
				Score:         &score,
				Message:       fmt.Sprintf("Azure Content Safety %s severity %d >= threshold %d", cat.Category, cat.Severity, thresh),
			})
		}
	}
	for _, bm := range parsed.BlocklistsMatch {
		violations = append(violations, domain.GuardrailViolation{
			GuardrailName: d.name,
			GuardrailID:   d.id,
			Provider:      ProviderAzureTextModerations,
			Category:      "blocklist",
			Rule:          bm.BlocklistName,
			Message:       fmt.Sprintf("Azure Content Safety blocklist %q matched item %q", bm.BlocklistName, bm.BlocklistItemText),
		})
	}

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
