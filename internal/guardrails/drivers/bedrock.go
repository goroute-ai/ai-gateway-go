package drivers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/adapter"
	adapterbedrock "github.com/goroute-ai/ai-gateway-go/internal/adapter/bedrock"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/guardrails"
)

// BedrockDriver evaluates inputs and outputs via AWS Bedrock Guardrails ApplyGuardrail API
// signed with AWS SigV4.
type BedrockDriver struct {
	name             string
	id               string
	guardrailID      string
	guardrailVersion string
	region           string
	endpoint         string
	signer           *adapterbedrock.SigV4Signer
	explicitAction   domain.GuardrailAction
	hasExplicitAct   bool
	httpClient       *http.Client
	nowFn            func() time.Time
}

// NewBedrockDriver constructs an AWS Bedrock Guardrails driver.
func NewBedrockDriver(cfg guardrails.DriverConfig, httpClient *http.Client) (guardrails.Driver, error) {
	grID := configString(cfg, "guardrail_id", "guardrailIdentifier")
	if grID == "" {
		return nil, fmt.Errorf("bedrock driver requires guardrail_id")
	}
	grVersion := configString(cfg, "guardrail_version", "guardrailVersion")
	if grVersion == "" {
		grVersion = "DRAFT"
	}

	region := resolveSecretOrConfig(cfg, "aws_region", "region")
	if region == "" {
		region = "us-east-1"
	}

	accessKey := resolveSecretOrConfig(cfg, "aws_access_key_id", "access_key_id")
	secretKey := resolveSecretOrConfig(cfg, "aws_secret_access_key", "secret_access_key")
	if accessKey == "" || secretKey == "" {
		return nil, fmt.Errorf("bedrock driver requires aws_access_key_id and aws_secret_access_key")
	}
	sessionToken := resolveSecretOrConfig(cfg, "aws_session_token", "session_token")

	baseURL := configString(cfg, "base_url", "endpoint")
	if baseURL == "" {
		baseURL = fmt.Sprintf("https://bedrock-runtime.%s.amazonaws.com", region)
	}
	baseURL = strings.TrimRight(baseURL, "/")

	endpoint := fmt.Sprintf("%s/guardrail/%s/version/%s/apply",
		baseURL,
		url.PathEscape(grID),
		url.PathEscape(grVersion),
	)

	explicitAct := normalizeActionString(string(cfg.EffectiveAction))
	if explicitAct == "" {
		explicitAct = normalizeActionString(configString(cfg, "action", "default_action"))
	}

	return &BedrockDriver{
		name:             guardrailName(cfg, ProviderBedrock),
		id:               guardrailID(cfg),
		guardrailID:      grID,
		guardrailVersion: grVersion,
		region:           region,
		endpoint:         endpoint,
		signer: &adapterbedrock.SigV4Signer{
			AccessKeyID:     accessKey,
			SecretAccessKey: secretKey,
			SessionToken:    sessionToken,
			Region:          region,
			Service:         "bedrock",
		},
		explicitAction: explicitAct,
		hasExplicitAct: explicitAct != "",
		httpClient:     resolveHTTPClient(httpClient),
		nowFn:          time.Now,
	}, nil
}

func (d *BedrockDriver) Name() string {
	return d.name
}

func (d *BedrockDriver) SupportedHooks() []domain.GuardrailHook {
	return defaultTextHooks()
}

type bedrockApplyRequest struct {
	Source  string                `json:"source"`
	Content []bedrockContentBlock `json:"content"`
}

type bedrockContentBlock struct {
	Text *bedrockTextBlock `json:"text,omitempty"`
}

type bedrockTextBlock struct {
	Text string `json:"text"`
}

type bedrockApplyResponse struct {
	Action      string               `json:"action"`
	Outputs     []bedrockOutputBlock `json:"outputs"`
	Assessments []bedrockAssessment  `json:"assessments"`
	Usage       bedrockUsage         `json:"usage"`
}

type bedrockOutputBlock struct {
	Text string `json:"text"`
}

type bedrockUsage struct {
	TopicPolicyUnits              int64 `json:"topicPolicyUnits"`
	ContentPolicyUnits            int64 `json:"contentPolicyUnits"`
	WordPolicyUnits               int64 `json:"wordPolicyUnits"`
	SensitiveInformationUnits     int64 `json:"sensitiveInformationPolicyUnits"`
	SensitiveInformationFreeUnits int64 `json:"sensitiveInformationPolicyFreeUnits"`
	ContextualGroundingUnits      int64 `json:"contextualGroundingPolicyUnits"`
}

type bedrockAssessment struct {
	TopicPolicy *struct {
		Topics []struct {
			Name   string `json:"name"`
			Type   string `json:"type"`
			Action string `json:"action"`
		} `json:"topics"`
	} `json:"topicPolicy"`
	ContentPolicy *struct {
		Filters []struct {
			Type       string `json:"type"`
			Confidence string `json:"confidence"`
			Action     string `json:"action"`
		} `json:"filters"`
	} `json:"contentPolicy"`
	WordPolicy *struct {
		CustomWords []struct {
			Match  string `json:"match"`
			Action string `json:"action"`
		} `json:"customWords"`
		ManagedWordLists []struct {
			Match  string `json:"match"`
			Type   string `json:"type"`
			Action string `json:"action"`
		} `json:"managedWordLists"`
	} `json:"wordPolicy"`
	SensitiveInformationPolicy *struct {
		PIIEntities []struct {
			Type   string `json:"type"`
			Match  string `json:"match"`
			Action string `json:"action"`
		} `json:"piiEntities"`
		Regexes []struct {
			Name   string `json:"name"`
			Match  string `json:"match"`
			Action string `json:"action"`
		} `json:"regexes"`
	} `json:"sensitiveInformationPolicy"`
	ContextualGroundingPolicy *struct {
		Filters []struct {
			Type      string  `json:"type"`
			Threshold float64 `json:"threshold"`
			Score     float64 `json:"score"`
			Action    string  `json:"action"`
		} `json:"filters"`
	} `json:"contextualGroundingPolicy"`
}

func (d *BedrockDriver) Evaluate(ctx context.Context, input *domain.GuardrailEvalInput) (*domain.GuardrailEvalResult, error) {
	texts := extractTexts(input)
	if !hasNonEmptyText(texts) {
		return &domain.GuardrailEvalResult{
			Decision:          domain.GuardrailDecisionAllow,
			AppliedGuardrails: []string{d.name},
		}, nil
	}

	source := "INPUT"
	if isOutputDirection(input) {
		source = "OUTPUT"
	}

	blocks := make([]bedrockContentBlock, 0, len(texts))
	nonEmptyIdx := make([]int, 0, len(texts))
	for i, t := range texts {
		if t != "" {
			blocks = append(blocks, bedrockContentBlock{Text: &bedrockTextBlock{Text: t}})
			nonEmptyIdx = append(nonEmptyIdx, i)
		}
	}

	reqBody, err := json.Marshal(bedrockApplyRequest{
		Source:  source,
		Content: blocks,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal bedrock request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.endpoint, bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("build bedrock request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	if err := d.signer.Sign(req, reqBody, d.nowFn().UTC()); err != nil {
		return nil, fmt.Errorf("sign bedrock request: %w", err)
	}

	resp, err := d.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("bedrock request failed: %w", err)
	}
	defer resp.Body.Close()

	respBytes, err := adapter.ReadBoundedBody(resp.Body, defaultMaxGuardrailResponseBytes, domain.ProviderBedrock)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("bedrock returned status %d: %s", resp.StatusCode, strings.TrimSpace(string(respBytes)))
	}

	var parsed bedrockApplyResponse
	if err := json.Unmarshal(respBytes, &parsed); err != nil {
		return nil, fmt.Errorf("decode bedrock response: %w", err)
	}

	usageUnits := parsed.Usage.TopicPolicyUnits +
		parsed.Usage.ContentPolicyUnits +
		parsed.Usage.WordPolicyUnits +
		parsed.Usage.SensitiveInformationUnits +
		parsed.Usage.SensitiveInformationFreeUnits +
		parsed.Usage.ContextualGroundingUnits
	if usageUnits == 0 {
		usageUnits = 1
	}

	intervened := strings.EqualFold(parsed.Action, "GUARDRAIL_INTERVENED") || strings.EqualFold(parsed.Action, "INTERVENED")
	if !intervened {
		return &domain.GuardrailEvalResult{
			Decision:          domain.GuardrailDecisionAllow,
			AppliedGuardrails: []string{d.name},
			UsageUnits:        usageUnits,
		}, nil
	}

	violations, hasBlocked, hasAnonymized := d.extractViolations(parsed.Assessments)
	if len(violations) == 0 {
		violations = []domain.GuardrailViolation{{
			GuardrailName: d.name,
			GuardrailID:   d.id,
			Provider:      ProviderBedrock,
			Category:      "bedrock_guardrail",
			Rule:          parsed.Action,
			Message:       "AWS Bedrock guardrail intervened",
		}}
	}

	// Determine final decision based on explicit action override and Bedrock assessment actions.
	decision := domain.GuardrailDecisionBlock
	switch {
	case d.hasExplicitAct && d.explicitAction == domain.GuardrailActionAudit:
		decision = domain.GuardrailDecisionFlag
	case d.hasExplicitAct && d.explicitAction == domain.GuardrailActionBlock:
		decision = domain.GuardrailDecisionBlock
	case (hasAnonymized && !hasBlocked || (d.hasExplicitAct && d.explicitAction == domain.GuardrailActionRedact)) && len(parsed.Outputs) > 0:
		decision = domain.GuardrailDecisionModify
	case !hasBlocked && len(parsed.Outputs) > 0 && hasAnonymizedOutput(texts, nonEmptyIdx, parsed.Outputs):
		decision = domain.GuardrailDecisionModify
	}

	res := &domain.GuardrailEvalResult{
		Decision:          decision,
		Violations:        violations,
		AppliedGuardrails: []string{d.name},
		UsageUnits:        usageUnits,
		ErrorMessage:      violations[0].Message,
	}

	if decision == domain.GuardrailDecisionModify {
		modified := make([]string, len(texts))
		copy(modified, texts)
		if len(parsed.Outputs) == len(nonEmptyIdx) {
			for i, idx := range nonEmptyIdx {
				modified[idx] = parsed.Outputs[i].Text
			}
		} else if len(parsed.Outputs) > 0 {
			joined := make([]string, 0, len(parsed.Outputs))
			for _, out := range parsed.Outputs {
				joined = append(joined, out.Text)
			}
			modified = []string{strings.Join(joined, "\n")}
		}
		res.ModifiedTexts = modified
	}

	for i := range res.Violations {
		res.Violations[i].Decision = decision
	}
	return res, nil
}

func hasAnonymizedOutput(origTexts []string, nonEmptyIdx []int, outputs []bedrockOutputBlock) bool {
	if len(outputs) == 0 {
		return false
	}
	if len(outputs) == len(nonEmptyIdx) {
		for i, idx := range nonEmptyIdx {
			if outputs[i].Text != origTexts[idx] {
				return true
			}
		}
	}
	return false
}

func (d *BedrockDriver) extractViolations(assessments []bedrockAssessment) (violations []domain.GuardrailViolation, hasBlocked bool, hasAnonymized bool) {
	recordAction := func(act string) {
		switch strings.ToUpper(strings.TrimSpace(act)) {
		case "BLOCKED":
			hasBlocked = true
		case "ANONYMIZED":
			hasAnonymized = true
		}
	}

	for _, a := range assessments {
		if a.TopicPolicy != nil {
			for _, t := range a.TopicPolicy.Topics {
				recordAction(t.Action)
				violations = append(violations, domain.GuardrailViolation{
					GuardrailName: d.name,
					GuardrailID:   d.id,
					Provider:      ProviderBedrock,
					Category:      "topic_policy",
					Rule:          t.Name,
					Severity:      t.Action,
					Message:       fmt.Sprintf("Bedrock topic policy %q (%s)", t.Name, t.Action),
				})
			}
		}
		if a.ContentPolicy != nil {
			for _, f := range a.ContentPolicy.Filters {
				recordAction(f.Action)
				violations = append(violations, domain.GuardrailViolation{
					GuardrailName: d.name,
					GuardrailID:   d.id,
					Provider:      ProviderBedrock,
					Category:      "content_policy",
					Rule:          f.Type,
					Severity:      f.Confidence,
					Message:       fmt.Sprintf("Bedrock content filter %q (%s/%s)", f.Type, f.Confidence, f.Action),
				})
			}
		}
		if a.WordPolicy != nil {
			for _, w := range a.WordPolicy.CustomWords {
				recordAction(w.Action)
				violations = append(violations, domain.GuardrailViolation{
					GuardrailName: d.name,
					GuardrailID:   d.id,
					Provider:      ProviderBedrock,
					Category:      "word_policy",
					Rule:          w.Match,
					Severity:      w.Action,
					Message:       fmt.Sprintf("Bedrock custom word policy matched (%s)", w.Action),
				})
			}
			for _, m := range a.WordPolicy.ManagedWordLists {
				recordAction(m.Action)
				violations = append(violations, domain.GuardrailViolation{
					GuardrailName: d.name,
					GuardrailID:   d.id,
					Provider:      ProviderBedrock,
					Category:      "managed_word_list",
					Rule:          m.Type,
					Severity:      m.Action,
					Message:       fmt.Sprintf("Bedrock managed word list %q matched (%s)", m.Type, m.Action),
				})
			}
		}
		if a.SensitiveInformationPolicy != nil {
			for _, p := range a.SensitiveInformationPolicy.PIIEntities {
				recordAction(p.Action)
				violations = append(violations, domain.GuardrailViolation{
					GuardrailName: d.name,
					GuardrailID:   d.id,
					Provider:      ProviderBedrock,
					Category:      "pii",
					Rule:          p.Type,
					Severity:      p.Action,
					Message:       fmt.Sprintf("Bedrock PII entity %q (%s)", p.Type, p.Action),
				})
			}
			for _, r := range a.SensitiveInformationPolicy.Regexes {
				recordAction(r.Action)
				violations = append(violations, domain.GuardrailViolation{
					GuardrailName: d.name,
					GuardrailID:   d.id,
					Provider:      ProviderBedrock,
					Category:      "regex",
					Rule:          r.Name,
					Severity:      r.Action,
					Message:       fmt.Sprintf("Bedrock regex %q (%s)", r.Name, r.Action),
				})
			}
		}
		if a.ContextualGroundingPolicy != nil {
			for _, g := range a.ContextualGroundingPolicy.Filters {
				recordAction(g.Action)
				score := g.Score
				violations = append(violations, domain.GuardrailViolation{
					GuardrailName: d.name,
					GuardrailID:   d.id,
					Provider:      ProviderBedrock,
					Category:      "contextual_grounding",
					Rule:          g.Type,
					Severity:      g.Action,
					Score:         &score,
					Message:       fmt.Sprintf("Bedrock contextual grounding %q failed (score=%.3f, threshold=%.3f)", g.Type, g.Score, g.Threshold),
				})
			}
		}
	}
	return violations, hasBlocked, hasAnonymized
}
