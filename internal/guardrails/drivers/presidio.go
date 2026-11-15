package drivers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/guardrails"
)

const (
	defaultPresidioLanguage       = "en"
	defaultPresidioScoreThreshold = 0.5
	defaultPresidioChunkSizeBytes = 4096
	defaultPresidioOverlapBytes   = 128
	defaultPresidioMaxConcurrency = 4
)

// presidioEntityGroups defines 50+ regional PII entity types grouped by region/standard.
var presidioEntityGroups = map[string][]string{
	"global": {
		"PERSON",
		"EMAIL_ADDRESS",
		"PHONE_NUMBER",
		"CREDIT_CARD",
		"CRYPTO",
		"DATE_TIME",
		"DOMAIN_NAME",
		"IBAN_CODE",
		"IP_ADDRESS",
		"NRP",
		"LOCATION",
		"MEDICAL_LICENSE",
		"URL",
	},
	"us": {
		"US_SSN",
		"US_BANK_NUMBER",
		"US_DRIVER_LICENSE",
		"US_ITIN",
		"US_PASSPORT",
		"US_MEDICARE_NUMBER",
	},
	"uk": {
		"UK_NHS",
		"UK_NINO",
		"UK_PASSPORT",
		"UK_DRIVER_LICENSE",
		"UK_UTR",
	},
	"eu": {
		"EU_VAT_ID",
		"EU_PASSPORT",
		"ES_NIF",
		"ES_NIE",
		"IT_FISCAL_CODE",
		"IT_DRIVER_LICENSE",
		"IT_VAT_CODE",
		"IT_PASSPORT",
		"IT_IDENTITY_CARD",
		"PL_PESEL",
		"DE_TAX_ID",
		"DE_PASSPORT",
		"FR_NIR",
		"FR_PASSPORT",
		"NL_BSN",
		"FI_PERSONAL_IDENTITY_CODE",
	},
	"au": {
		"AU_ABN",
		"AU_ACN",
		"AU_TFN",
		"AU_MEDICARE",
		"AU_PASSPORT",
	},
	"in": {
		"IN_PAN",
		"IN_AADHAAR",
		"IN_VEHICLE_REGISTRATION",
		"IN_VOTER",
		"IN_PASSPORT",
	},
	"sg": {
		"SG_NRIC_FIN",
		"SG_UEN",
		"SG_PASSPORT",
	},
	"ca": {
		"CA_SIN",
		"CA_PASSPORT",
	},
	"apac": {
		"JP_MY_NUMBER",
		"KR_RRN",
	},
	"latam": {
		"BR_CPF",
		"BR_CNPJ",
	},
}

// PresidioEntityGroups returns a copy of the regional PII entity groups supported by the Presidio driver.
func PresidioEntityGroups() map[string][]string {
	out := make(map[string][]string, len(presidioEntityGroups))
	for group, entities := range presidioEntityGroups {
		cp := make([]string, len(entities))
		copy(cp, entities)
		out[group] = cp
	}
	return out
}

// AllPresidioEntityTypes returns the sorted deduplicated list of all 50+ built-in PII entity types.
func AllPresidioEntityTypes() []string {
	seen := make(map[string]struct{}, 64)
	for _, list := range presidioEntityGroups {
		for _, entity := range list {
			seen[entity] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for entity := range seen {
		out = append(out, entity)
	}
	sort.Strings(out)
	return out
}

// ResolvePresidioEntities expands named regional groups and explicit entity names into a deduplicated slice.
func ResolvePresidioEntities(entities, groups []string) []string {
	seen := make(map[string]struct{})
	var out []string
	add := func(e string) {
		norm := strings.ToUpper(strings.TrimSpace(e))
		if norm == "" {
			return
		}
		if _, ok := seen[norm]; ok {
			return
		}
		seen[norm] = struct{}{}
		out = append(out, norm)
	}
	for _, g := range groups {
		key := strings.ToLower(strings.TrimSpace(g))
		if key == "all" {
			for _, e := range AllPresidioEntityTypes() {
				add(e)
			}
			continue
		}
		if list, ok := presidioEntityGroups[key]; ok {
			for _, e := range list {
				add(e)
			}
		}
	}
	for _, e := range entities {
		add(e)
	}
	return out
}

// PresidioDriver integrates Microsoft Presidio Analyzer and Anonymizer with regional entity groups,
// score thresholds, byte-chunked parallel scanning, and per-request metadata overrides.
type PresidioDriver struct {
	name              string
	id                string
	analyzerEndpoint  string
	anonymizerEndpt   string
	apiKey            string
	language          string
	entities          []string
	scoreThreshold    float64
	entityThresholds  map[string]float64
	chunkSizeBytes    int
	chunkOverlapBytes int
	maxConcurrency    int
	anonymizers       map[string]any
	action            domain.GuardrailAction
	httpClient        *http.Client
}

// NewPresidioDriver constructs a Microsoft Presidio Analyzer + Anonymizer driver.
func NewPresidioDriver(cfg guardrails.DriverConfig, httpClient *http.Client) (guardrails.Driver, error) {
	analyzerBase := configString(cfg, "analyzer_base_url", "analyzer_url", "base_url", "api_base", "endpoint")
	if analyzerBase == "" {
		return nil, fmt.Errorf("presidio driver requires analyzer_base_url or base_url")
	}
	analyzerEndpoint := resolvePresidioURL(analyzerBase, "/analyze")

	anonymizerBase := configString(cfg, "anonymizer_base_url", "anonymizer_url")
	anonymizerEndpoint := ""
	if anonymizerBase != "" {
		anonymizerEndpoint = resolvePresidioURL(anonymizerBase, "/anonymize")
	}

	language := configString(cfg, "language")
	if language == "" {
		language = defaultPresidioLanguage
	}

	groups := configStringSlice(cfg, "entity_groups", "pii_entity_groups")
	explicitEntities := configStringSlice(cfg, "entities", "pii_entities")
	entities := ResolvePresidioEntities(explicitEntities, groups)

	scoreThresh := configFloat(cfg, defaultPresidioScoreThreshold, "score_threshold", "threshold")
	if scoreThresh < 0 {
		scoreThresh = 0
	}

	rawEntityThresholds := configFloatMap(cfg, "entity_thresholds", "score_thresholds", "category_thresholds")
	entityThresholds := make(map[string]float64, len(rawEntityThresholds))
	for k, v := range rawEntityThresholds {
		entityThresholds[strings.ToUpper(strings.TrimSpace(k))] = v
	}

	chunkSize := configInt(cfg, defaultPresidioChunkSizeBytes, "chunk_size_bytes")
	if chunkSize <= 0 {
		chunkSize = defaultPresidioChunkSizeBytes
	}
	overlapBytes := configInt(cfg, defaultPresidioOverlapBytes, "chunk_overlap_bytes")
	if overlapBytes < 0 {
		overlapBytes = 0
	}
	if overlapBytes >= chunkSize {
		overlapBytes = chunkSize / 4
	}
	maxConc := configInt(cfg, defaultPresidioMaxConcurrency, "max_concurrency")
	if maxConc <= 0 {
		maxConc = defaultPresidioMaxConcurrency
	}

	return &PresidioDriver{
		name:              guardrailName(cfg, ProviderPresidio),
		id:                guardrailID(cfg),
		analyzerEndpoint:  analyzerEndpoint,
		anonymizerEndpt:   anonymizerEndpoint,
		apiKey:            resolveSecretOrConfig(cfg, "api_key", "presidio_api_key", "token"),
		language:          language,
		entities:          entities,
		scoreThreshold:    scoreThresh,
		entityThresholds:  entityThresholds,
		chunkSizeBytes:    chunkSize,
		chunkOverlapBytes: overlapBytes,
		maxConcurrency:    maxConc,
		anonymizers:       configAnyMap(cfg, "anonymizers"),
		action:            effectiveAction(cfg, domain.GuardrailActionRedact),
		httpClient:        resolveHTTPClient(httpClient),
	}, nil
}

func resolvePresidioURL(baseURL, suffix string) string {
	trimmed := strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if strings.HasSuffix(trimmed, suffix) {
		return trimmed
	}
	return trimmed + suffix
}

func (d *PresidioDriver) Name() string {
	return d.name
}

func (d *PresidioDriver) SupportedHooks() []domain.GuardrailHook {
	return defaultTextHooks()
}

type presidioAnalyzeRequest struct {
	Text           string   `json:"text"`
	Language       string   `json:"language"`
	Entities       []string `json:"entities,omitempty"`
	ScoreThreshold float64  `json:"score_threshold,omitempty"`
}

type presidioEntityMatch struct {
	EntityType string  `json:"entity_type"`
	Start      int     `json:"start"`
	End        int     `json:"end"`
	Score      float64 `json:"score"`
}

type presidioAnonymizeRequest struct {
	Text            string                `json:"text"`
	AnalyzerResults []presidioEntityMatch `json:"analyzer_results"`
	Anonymizers     map[string]any        `json:"anonymizers,omitempty"`
}

type presidioAnonymizeResponse struct {
	Text string `json:"text"`
}

type presidioEvalOverrides struct {
	entities       []string
	language       string
	scoreThreshold float64
	action         domain.GuardrailAction
}

func (d *PresidioDriver) resolveRequestOverrides(input *domain.GuardrailEvalInput) presidioEvalOverrides {
	ov := presidioEvalOverrides{
		entities:       d.entities,
		language:       d.language,
		scoreThreshold: d.scoreThreshold,
		action:         d.action,
	}
	if input == nil || len(input.Metadata) == 0 {
		return ov
	}

	if lang, ok := lookupStringCaseInsensitive(input.Metadata, "language"); ok && lang != "" {
		ov.language = lang
	}
	if rawThresh, ok := lookupAnyCaseInsensitive(input.Metadata, "score_threshold"); ok {
		if f, ok := floatFromAny(rawThresh); ok && f >= 0 {
			ov.scoreThreshold = f
		}
	} else if rawThresh, ok := lookupAnyCaseInsensitive(input.Metadata, "threshold"); ok {
		if f, ok := floatFromAny(rawThresh); ok && f >= 0 {
			ov.scoreThreshold = f
		}
	}

	if rawAct, ok := lookupStringCaseInsensitive(input.Metadata, "action"); ok && rawAct != "" {
		if act := normalizeActionString(rawAct); act != "" {
			ov.action = act
		}
	}

	var reqEntities, reqGroups []string
	if rawEnt, ok := lookupAnyCaseInsensitive(input.Metadata, "pii_entities"); ok {
		reqEntities = stringSliceFromAny(rawEnt)
	} else if rawEnt, ok := lookupAnyCaseInsensitive(input.Metadata, "entities"); ok {
		reqEntities = stringSliceFromAny(rawEnt)
	}
	if rawGrp, ok := lookupAnyCaseInsensitive(input.Metadata, "pii_entity_groups"); ok {
		reqGroups = stringSliceFromAny(rawGrp)
	} else if rawGrp, ok := lookupAnyCaseInsensitive(input.Metadata, "entity_groups"); ok {
		reqGroups = stringSliceFromAny(rawGrp)
	}
	if len(reqEntities) > 0 || len(reqGroups) > 0 {
		ov.entities = ResolvePresidioEntities(reqEntities, reqGroups)
	}
	return ov
}

func (d *PresidioDriver) Evaluate(ctx context.Context, input *domain.GuardrailEvalInput) (*domain.GuardrailEvalResult, error) {
	texts := extractTexts(input)
	if !hasNonEmptyText(texts) {
		return &domain.GuardrailEvalResult{
			Decision:          domain.GuardrailDecisionAllow,
			AppliedGuardrails: []string{d.name},
		}, nil
	}

	ov := d.resolveRequestOverrides(input)
	modified := make([]string, len(texts))
	copy(modified, texts)

	var violations []domain.GuardrailViolation
	var totalUnits int64
	changed := false

	for idx, text := range texts {
		if strings.TrimSpace(text) == "" {
			continue
		}
		matches, units, err := d.analyzeTextChunked(ctx, text, ov)
		if err != nil {
			return nil, err
		}
		totalUnits += units
		if len(matches) == 0 {
			continue
		}

		for _, m := range matches {
			score := m.Score
			violations = append(violations, domain.GuardrailViolation{
				GuardrailName: d.name,
				GuardrailID:   d.id,
				Provider:      ProviderPresidio,
				Category:      "pii",
				Rule:          m.EntityType,
				Score:         &score,
				Message:       fmt.Sprintf("Presidio detected %s (score=%.2f)", m.EntityType, m.Score),
				Details: map[string]any{
					"start": m.Start,
					"end":   m.End,
				},
			})
		}

		if ov.action == domain.GuardrailActionRedact {
			anonText, err := d.anonymizeText(ctx, text, matches)
			if err != nil {
				return nil, err
			}
			if anonText != text {
				modified[idx] = anonText
				changed = true
			}
		}
	}

	if totalUnits == 0 {
		totalUnits = 1
	}

	if len(violations) == 0 {
		return &domain.GuardrailEvalResult{
			Decision:          domain.GuardrailDecisionAllow,
			AppliedGuardrails: []string{d.name},
			UsageUnits:        totalUnits,
		}, nil
	}

	decision := domain.GuardrailDecisionBlock
	switch ov.action {
	case domain.GuardrailActionAudit:
		decision = domain.GuardrailDecisionFlag
	case domain.GuardrailActionRedact:
		decision = domain.GuardrailDecisionModify
	}

	for i := range violations {
		violations[i].Decision = decision
		violations[i].Action = ov.action
	}

	res := &domain.GuardrailEvalResult{
		Decision:          decision,
		Violations:        violations,
		AppliedGuardrails: []string{d.name},
		UsageUnits:        totalUnits,
		ErrorMessage:      violations[0].Message,
	}
	if decision == domain.GuardrailDecisionModify && changed {
		res.ModifiedTexts = modified
	}
	return res, nil
}

type textRuneChunk struct {
	text           string
	baseRuneOffset int
}

func splitTextIntoRuneChunks(text string, chunkSizeBytes, overlapBytes int) []textRuneChunk {
	if len(text) <= chunkSizeBytes || chunkSizeBytes <= 0 {
		return []textRuneChunk{{text: text, baseRuneOffset: 0}}
	}

	var chunks []textRuneChunk
	startByte := 0
	startRune := 0

	for startByte < len(text) {
		endByte := startByte + chunkSizeBytes
		if endByte >= len(text) {
			chunks = append(chunks, textRuneChunk{
				text:           text[startByte:],
				baseRuneOffset: startRune,
			})
			break
		}
		for endByte > startByte && !utf8.RuneStart(text[endByte]) {
			endByte--
		}
		if endByte == startByte {
			_, w := utf8.DecodeRuneInString(text[startByte:])
			endByte = startByte + w
		}

		chunks = append(chunks, textRuneChunk{
			text:           text[startByte:endByte],
			baseRuneOffset: startRune,
		})

		nextStartByte := endByte - overlapBytes
		if nextStartByte <= startByte {
			nextStartByte = endByte
		}
		for nextStartByte < endByte && !utf8.RuneStart(text[nextStartByte]) {
			nextStartByte++
		}
		startRune += utf8.RuneCountInString(text[startByte:nextStartByte])
		startByte = nextStartByte
	}
	return chunks
}

func (d *PresidioDriver) analyzeTextChunked(ctx context.Context, text string, ov presidioEvalOverrides) ([]presidioEntityMatch, int64, error) {
	chunks := splitTextIntoRuneChunks(text, d.chunkSizeBytes, d.chunkOverlapBytes)
	if len(chunks) == 1 {
		matches, err := d.callAnalyze(ctx, chunks[0].text, ov)
		if err != nil {
			return nil, 0, err
		}
		return d.filterAndDeduplicate(matches, ov.scoreThreshold), 1, nil
	}

	chunkResults := make([][]presidioEntityMatch, len(chunks))
	chunkErrs := make([]error, len(chunks))

	sem := make(chan struct{}, d.maxConcurrency)
	var wg sync.WaitGroup
	for i, ch := range chunks {
		wg.Add(1)
		go func(idx int, c textRuneChunk) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				chunkErrs[idx] = ctx.Err()
				return
			}
			matches, err := d.callAnalyze(ctx, c.text, ov)
			if err != nil {
				chunkErrs[idx] = err
				return
			}
			for j := range matches {
				matches[j].Start += c.baseRuneOffset
				matches[j].End += c.baseRuneOffset
			}
			chunkResults[idx] = matches
		}(i, ch)
	}
	wg.Wait()

	for _, err := range chunkErrs {
		if err != nil {
			return nil, 0, err
		}
	}

	var combined []presidioEntityMatch
	for _, res := range chunkResults {
		combined = append(combined, res...)
	}
	return d.filterAndDeduplicate(combined, ov.scoreThreshold), int64(len(chunks)), nil
}

func (d *PresidioDriver) callAnalyze(ctx context.Context, text string, ov presidioEvalOverrides) ([]presidioEntityMatch, error) {
	// Use minimum configured threshold for the wire request so per-entity overrides can filter accurately.
	wireThresh := ov.scoreThreshold
	for _, t := range d.entityThresholds {
		if t < wireThresh {
			wireThresh = t
		}
	}

	reqPayload := presidioAnalyzeRequest{
		Text:           text,
		Language:       ov.language,
		Entities:       ov.entities,
		ScoreThreshold: wireThresh,
	}

	headers := map[string]string{}
	if d.apiKey != "" {
		headers["Authorization"] = "Bearer " + d.apiKey
	}

	status, body, err := doJSONRequest(ctx, d.httpClient, http.MethodPost, d.analyzerEndpoint, headers, reqPayload, domain.ProviderType("presidio"))
	if err != nil {
		return nil, err
	}
	if status < 200 || status >= 300 {
		return nil, fmt.Errorf("presidio analyzer returned status %d: %s", status, strings.TrimSpace(string(body)))
	}

	var matches []presidioEntityMatch
	if err := json.Unmarshal(body, &matches); err != nil {
		return nil, fmt.Errorf("decode presidio analyzer response: %w", err)
	}
	return matches, nil
}

func (d *PresidioDriver) filterAndDeduplicate(matches []presidioEntityMatch, defaultThresh float64) []presidioEntityMatch {
	var filtered []presidioEntityMatch
	for _, m := range matches {
		if m.End <= m.Start || m.Start < 0 {
			continue
		}
		thresh := defaultThresh
		if custom, ok := d.entityThresholds[strings.ToUpper(strings.TrimSpace(m.EntityType))]; ok {
			thresh = custom
		}
		if m.Score < thresh {
			continue
		}
		filtered = append(filtered, m)
	}
	if len(filtered) <= 1 {
		return filtered
	}

	sort.Slice(filtered, func(i, j int) bool {
		if filtered[i].Start != filtered[j].Start {
			return filtered[i].Start < filtered[j].Start
		}
		if filtered[i].Score != filtered[j].Score {
			return filtered[i].Score > filtered[j].Score
		}
		return filtered[i].End > filtered[j].End
	})

	dedup := make([]presidioEntityMatch, 0, len(filtered))
	for _, m := range filtered {
		merged := false
		for i := range dedup {
			prev := &dedup[i]
			if m.Start < prev.End && m.End > prev.Start {
				// Overlapping span from chunk overlap or overlapping detector.
				if strings.EqualFold(prev.EntityType, m.EntityType) {
					if m.End > prev.End {
						prev.End = m.End
					}
					if m.Score > prev.Score {
						prev.Score = m.Score
					}
					merged = true
					break
				}
			}
		}
		if !merged {
			dedup = append(dedup, m)
		}
	}
	return dedup
}

func (d *PresidioDriver) anonymizeText(ctx context.Context, text string, matches []presidioEntityMatch) (string, error) {
	if d.anonymizerEndpt != "" {
		reqPayload := presidioAnonymizeRequest{
			Text:            text,
			AnalyzerResults: matches,
			Anonymizers:     d.anonymizers,
		}
		headers := map[string]string{}
		if d.apiKey != "" {
			headers["Authorization"] = "Bearer " + d.apiKey
		}
		status, body, err := doJSONRequest(ctx, d.httpClient, http.MethodPost, d.anonymizerEndpt, headers, reqPayload, domain.ProviderType("presidio"))
		if err != nil {
			return "", err
		}
		if status < 200 || status >= 300 {
			return "", fmt.Errorf("presidio anonymizer returned status %d: %s", status, strings.TrimSpace(string(body)))
		}
		var parsed presidioAnonymizeResponse
		if err := json.Unmarshal(body, &parsed); err != nil {
			return "", fmt.Errorf("decode presidio anonymizer response: %w", err)
		}
		return parsed.Text, nil
	}

	return anonymizeRunesLocally(text, matches), nil
}

func anonymizeRunesLocally(text string, matches []presidioEntityMatch) string {
	if len(matches) == 0 || text == "" {
		return text
	}
	runes := []rune(text)
	// Resolve overlapping spans of different types by keeping highest score / earliest start.
	sorted := make([]presidioEntityMatch, len(matches))
	copy(sorted, matches)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Start != sorted[j].Start {
			return sorted[i].Start < sorted[j].Start
		}
		return sorted[i].Score > sorted[j].Score
	})

	var nonOverlapping []presidioEntityMatch
	for _, m := range sorted {
		if m.Start >= len(runes) {
			continue
		}
		if m.End > len(runes) {
			m.End = len(runes)
		}
		if len(nonOverlapping) > 0 && m.Start < nonOverlapping[len(nonOverlapping)-1].End {
			continue
		}
		nonOverlapping = append(nonOverlapping, m)
	}

	var b strings.Builder
	cursor := 0
	for _, m := range nonOverlapping {
		if m.Start > cursor {
			b.WriteString(string(runes[cursor:m.Start]))
		}
		entity := strings.ToUpper(strings.TrimSpace(m.EntityType))
		if entity == "" {
			entity = "PII"
		}
		b.WriteString("<" + entity + ">")
		cursor = m.End
	}
	if cursor < len(runes) {
		b.WriteString(string(runes[cursor:]))
	}
	return b.String()
}
