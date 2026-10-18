package guardrails

import (
	"embed"
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"unicode"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"golang.org/x/text/unicode/norm"
)

//go:embed toxicity_packs/*.json
var toxicityPacksFS embed.FS

// ToxicityCategoryPack defines a built-in content/toxicity category pack.
type ToxicityCategoryPack struct {
	CategoryName  string            `json:"category_name"`
	DefaultAction string            `json:"default_action"`
	Keywords      []ToxicityKeyword `json:"keywords"`
	Exceptions    []string          `json:"exceptions,omitempty"`
}

// ToxicityKeyword defines a term and its severity level within a category pack.
type ToxicityKeyword struct {
	Term     string `json:"term"`
	Severity string `json:"severity"`
}

// ToxicityMatch records a single matched toxicity term.
type ToxicityMatch struct {
	Category string
	Term     string
	Severity string
}

type compiledToxicityKeyword struct {
	term     string
	severity string
	sevLevel int
	re       *regexp.Regexp
}

type compiledToxicityPack struct {
	name          string
	defaultAction domain.GuardrailAction
	keywords      []compiledToxicityKeyword
	exceptions    []string
	maxTermLen    int
}

var compiledToxicityPacks map[string]*compiledToxicityPack

func init() {
	compiledToxicityPacks = make(map[string]*compiledToxicityPack)
	entries, err := toxicityPacksFS.ReadDir("toxicity_packs")
	if err != nil {
		panic(fmt.Sprintf("guardrails: failed to read embedded toxicity_packs: %v", err))
	}
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		raw, err := toxicityPacksFS.ReadFile(filepath.ToSlash(filepath.Join("toxicity_packs", entry.Name())))
		if err != nil {
			panic(fmt.Sprintf("guardrails: failed to read toxicity pack %s: %v", entry.Name(), err))
		}
		var pack ToxicityCategoryPack
		if err := json.Unmarshal(raw, &pack); err != nil {
			panic(fmt.Sprintf("guardrails: failed to parse toxicity pack %s: %v", entry.Name(), err))
		}
		compiled := &compiledToxicityPack{
			name:          strings.ToLower(strings.TrimSpace(pack.CategoryName)),
			defaultAction: parseGuardrailAction(pack.DefaultAction, domain.GuardrailActionBlock),
		}
		for _, kw := range pack.Keywords {
			normTerm := normalizeTextForSignatureCheck(kw.Term)
			if normTerm == "" {
				continue
			}
			sev := strings.ToLower(strings.TrimSpace(kw.Severity))
			if sev == "" {
				sev = "medium"
			}
			// Compile word-boundary-aware pattern on normalized text.
			pattern := `(?i)(?:^|[^a-z0-9])(` + regexp.QuoteMeta(normTerm) + `)(?:$|[^a-z0-9])`
			re := regexp.MustCompile(pattern)
			compiled.keywords = append(compiled.keywords, compiledToxicityKeyword{
				term:     normTerm,
				severity: sev,
				sevLevel: severityLevel(sev),
				re:       re,
			})
			if len(normTerm) > compiled.maxTermLen {
				compiled.maxTermLen = len(normTerm)
			}
		}
		for _, exc := range pack.Exceptions {
			normExc := normalizeTextForSignatureCheck(exc)
			if normExc != "" {
				compiled.exceptions = append(compiled.exceptions, normExc)
				if len(normExc) > compiled.maxTermLen {
					compiled.maxTermLen = len(normExc)
				}
			}
		}
		compiledToxicityPacks[compiled.name] = compiled
	}
}

func parseGuardrailAction(raw string, fallback domain.GuardrailAction) domain.GuardrailAction {
	switch domain.GuardrailAction(strings.ToLower(strings.TrimSpace(raw))) {
	case domain.GuardrailActionBlock:
		return domain.GuardrailActionBlock
	case domain.GuardrailActionRedact:
		return domain.GuardrailActionRedact
	case domain.GuardrailActionAudit:
		return domain.GuardrailActionAudit
	default:
		return fallback
	}
}

func severityLevel(s string) int {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "low":
		return 0
	case "high":
		return 2
	case "medium", "":
		return 1
	default:
		return 1
	}
}

func shouldApplySeverity(severity, threshold string) bool {
	return severityLevel(severity) >= severityLevel(threshold)
}

// normalizeTextForSignatureCheck applies NFKC normalization, strips zero-width/format
// characters (unicode.Cf), lowercases, and collapses whitespace runs to single spaces.
func normalizeTextForSignatureCheck(s string) string {
	if s == "" {
		return ""
	}
	nfkc := norm.NFKC.String(s)
	var b strings.Builder
	b.Grow(len(nfkc))
	inSpace := false
	for _, r := range nfkc {
		if unicode.Is(unicode.Cf, r) {
			continue
		}
		if unicode.IsSpace(r) {
			if !inSpace && b.Len() > 0 {
				b.WriteByte(' ')
				inSpace = true
			}
			continue
		}
		inSpace = false
		b.WriteRune(unicode.ToLower(r))
	}
	return strings.TrimSpace(b.String())
}

type textSpan struct {
	start int
	end   int
}

func findExceptionSpans(normText string, packExceptions, policyExceptions []string) []textSpan {
	var spans []textSpan
	collect := func(exceptions []string) {
		for _, exc := range exceptions {
			if exc == "" {
				continue
			}
			offset := 0
			for {
				idx := strings.Index(normText[offset:], exc)
				if idx < 0 {
					break
				}
				start := offset + idx
				end := start + len(exc)
				spans = append(spans, textSpan{start: start, end: end})
				offset = start + 1
			}
		}
	}
	collect(packExceptions)
	collect(policyExceptions)
	return spans
}

func isWithinSpans(start, end int, spans []textSpan) bool {
	for _, sp := range spans {
		if start >= sp.start && end <= sp.end {
			return true
		}
	}
	return false
}

func resolveEnabledPacks(pol *domain.GuardrailPolicy) []*compiledToxicityPack {
	if pol == nil {
		return nil
	}
	var names []string
	if len(pol.EnabledContentCategories) == 0 {
		for name := range compiledToxicityPacks {
			names = append(names, name)
		}
		sort.Strings(names)
	} else {
		seen := make(map[string]struct{}, len(pol.EnabledContentCategories))
		for _, raw := range pol.EnabledContentCategories {
			name := strings.ToLower(strings.TrimSpace(raw))
			if name == "" {
				continue
			}
			if _, ok := seen[name]; ok {
				continue
			}
			seen[name] = struct{}{}
			names = append(names, name)
		}
	}

	packs := make([]*compiledToxicityPack, 0, len(names))
	for _, name := range names {
		if p, ok := compiledToxicityPacks[name]; ok {
			packs = append(packs, p)
		}
	}
	return packs
}

func longestToxicityPatternLen(pol *domain.GuardrailPolicy) int {
	if pol == nil || !pol.EnableToxicityFilter {
		return 0
	}
	maxLen := 0
	for _, p := range resolveEnabledPacks(pol) {
		if p.maxTermLen > maxLen {
			maxLen = p.maxTermLen
		}
	}
	for _, exc := range pol.ContentExceptions {
		if n := len(normalizeTextForSignatureCheck(exc)); n > maxLen {
			maxLen = n
		}
	}
	return maxLen
}

func scanToxicityText(pol *domain.GuardrailPolicy, text string) ([]ToxicityMatch, domain.GuardrailAction) {
	if pol == nil || !pol.EnableToxicityFilter || text == "" {
		return nil, ""
	}
	normText := normalizeTextForSignatureCheck(text)
	if normText == "" {
		return nil, ""
	}

	policyExceptions := make([]string, 0, len(pol.ContentExceptions))
	for _, exc := range pol.ContentExceptions {
		if n := normalizeTextForSignatureCheck(exc); n != "" {
			policyExceptions = append(policyExceptions, n)
		}
	}

	var matches []ToxicityMatch
	effectiveAction := pol.ToxicityAction

	for _, pack := range resolveEnabledPacks(pol) {
		excSpans := findExceptionSpans(normText, pack.exceptions, policyExceptions)
		for _, kw := range pack.keywords {
			if !shouldApplySeverity(kw.severity, pol.ToxicityThreshold) {
				continue
			}
			locs := kw.re.FindAllStringSubmatchIndex(normText, -1)
			matched := false
			for _, loc := range locs {
				// Group 1 is the exact term span.
				if len(loc) < 4 {
					continue
				}
				tStart, tEnd := loc[2], loc[3]
				if isWithinSpans(tStart, tEnd, excSpans) {
					continue
				}
				matched = true
				break
			}
			if matched {
				matches = append(matches, ToxicityMatch{
					Category: pack.name,
					Term:     kw.term,
					Severity: kw.severity,
				})
				if effectiveAction == "" {
					effectiveAction = pack.defaultAction
				}
			}
		}
	}

	if len(matches) > 0 && effectiveAction == "" {
		effectiveAction = domain.GuardrailActionBlock
	}
	return matches, effectiveAction
}

func computeToxicityRiskScore(matches []ToxicityMatch, text string, blocked bool) float64 {
	if len(matches) == 0 {
		return 0
	}
	if blocked {
		return 10.0
	}
	totalWords := len(strings.Fields(text))
	if totalWords < 1 {
		totalWords = 1
	}
	ratio := float64(len(matches)) / float64(totalWords)
	count := len(matches)
	if count > 5 {
		count = 5
	}
	score := ratio*7.0 + float64(count)*0.6
	if score < 2.0 {
		score = 2.0
	}
	if score > 10.0 {
		score = 10.0
	}
	return score
}

func redactToxicityTerms(text string, matches []ToxicityMatch, policyExceptions []string) (string, bool) {
	if len(matches) == 0 || text == "" {
		return text, false
	}
	updated := text
	changed := false
	for _, m := range matches {
		// Build a case-insensitive pattern allowing flexible whitespace between words in the term.
		words := strings.Fields(m.Term)
		if len(words) == 0 {
			continue
		}
		quoted := make([]string, len(words))
		for i, w := range words {
			quoted[i] = regexp.QuoteMeta(w)
		}
		pat := `(?i)\b` + strings.Join(quoted, `\s+`) + `\b`
		re, err := regexp.Compile(pat)
		if err != nil {
			continue
		}
		// Check exception spans on normalized current text before replacing.
		pack := compiledToxicityPacks[m.Category]
		var packExc []string
		if pack != nil {
			packExc = pack.exceptions
		}
		normUpdated := normalizeTextForSignatureCheck(updated)
		excSpans := findExceptionSpans(normUpdated, packExc, policyExceptions)
		if len(excSpans) == 0 {
			next := re.ReplaceAllString(updated, "[REDACTED_TOXICITY]")
			if next != updated {
				updated = next
				changed = true
			}
			continue
		}
		// Selective replacement: only replace occurrences not covered by an exception phrase.
		next := re.ReplaceAllStringFunc(updated, func(hit string) string {
			normHit := normalizeTextForSignatureCheck(hit)
			for _, sp := range excSpans {
				if strings.Contains(normUpdated[sp.start:sp.end], normHit) {
					return hit
				}
			}
			changed = true
			return "[REDACTED_TOXICITY]"
		})
		updated = next
	}
	return updated, changed
}

func evaluateToxicity(pol *domain.GuardrailPolicy, loggingOnly bool, text *string, isOutput bool, outcome *CheckOutcome) error {
	if pol == nil || !pol.EnableToxicityFilter || text == nil || *text == "" {
		return nil
	}
	matches, action := scanToxicityText(pol, *text)
	if len(matches) == 0 {
		return nil
	}

	for _, m := range matches {
		outcome.Violations = append(outcome.Violations, fmt.Sprintf("toxicity:%s:%s:%s", m.Category, m.Severity, m.Term))
	}

	if loggingOnly {
		outcome.AppliedAction = domain.GuardrailActionAudit
		if score := computeToxicityRiskScore(matches, *text, false); score > outcome.RiskScore {
			outcome.RiskScore = score
		}
		return nil
	}

	outcome.AppliedAction = action
	if action == domain.GuardrailActionBlock {
		outcome.RiskScore = 10.0
		if isOutput {
			return &domain.GatewayError{
				StatusCode: http.StatusBadGateway,
				Type:       domain.ErrorTypeServer,
				Code:       "guardrail_output_toxicity_detected",
				Message:    "Response blocked by organization toxicity guardrail policy",
			}
		}
		return &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "guardrail_toxicity_detected",
			Message:    "Request blocked by organization toxicity guardrail policy",
		}
	}

	if score := computeToxicityRiskScore(matches, *text, false); score > outcome.RiskScore {
		outcome.RiskScore = score
	}

	if action == domain.GuardrailActionRedact {
		policyExceptions := make([]string, 0, len(pol.ContentExceptions))
		for _, exc := range pol.ContentExceptions {
			if n := normalizeTextForSignatureCheck(exc); n != "" {
				policyExceptions = append(policyExceptions, n)
			}
		}
		if redacted, changed := redactToxicityTerms(*text, matches, policyExceptions); changed {
			*text = redacted
			outcome.Redacted = true
		}
	}

	return nil
}
