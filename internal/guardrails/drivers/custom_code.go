package drivers

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/guardrails"
	"github.com/goroute-ai/ai-gateway-go/internal/security/network"
	"go.starlark.net/starlark"
	"go.starlark.net/syntax"
)

const (
	// CustomCodeProvider identifies the sandboxed Starlark guardrail driver.
	CustomCodeProvider = "custom_code"

	defaultExecutionTimeout  = 250 * time.Millisecond
	maxExecutionTimeout      = 10 * time.Second
	defaultMaxExecutionSteps = uint64(50000)
	maxAllowedExecutionSteps = uint64(500000)
	maxHTTPResponseBytes     = int64(1 << 20) // 1 MiB
	maxJSONDepth             = 64
	maxRegexCacheEntries     = 256
	threadCtxLocalKey        = "goroute.custom_code.ctx"
)

var starlarkFileOptions = &syntax.FileOptions{
	Set:             true,
	While:           false,
	TopLevelControl: true,
	GlobalReassign:  false,
	Recursion:       false,
}

var defaultSupportedHooks = []domain.GuardrailHook{
	domain.GuardrailHookPreCall,
	domain.GuardrailHookDuringCall,
	domain.GuardrailHookPostCall,
	domain.GuardrailHookLoggingOnly,
	domain.GuardrailHookPreMCPCall,
	domain.GuardrailHookDuringMCPCall,
	domain.GuardrailHookPostMCPCall,
}

var sensitiveHeaderNames = map[string]struct{}{
	"authorization":       {},
	"cookie":              {},
	"proxy-authorization": {},
	"set-cookie":          {},
	"x-api-key":           {},
}

// CustomCodeDriver evaluates tenant-configured Starlark scripts inside a bounded,
// side-effect-controlled sandbox implementing guardrails.Driver.
type CustomCodeDriver struct {
	guardrailName string
	guardrailID   string
	hooks         []domain.GuardrailHook
	program       *starlark.Program
	httpClient    *http.Client
	allowHTTP     bool
	timeout       time.Duration
	maxSteps      uint64
	regexMu       sync.RWMutex
	regexCache    map[string]*regexp.Regexp
}

// NewCustomCodeDriver compiles and validates a Starlark custom_code guardrail driver.
// When httpClient is nil, outbound requests use network.NewHTTPClient with strict SSRF protection.
func NewCustomCodeDriver(cfg guardrails.DriverConfig, httpClient *http.Client) (*CustomCodeDriver, error) {
	return NewCustomCodeDriverWithPolicy(cfg, nil, httpClient)
}

// NewCustomCodeDriverWithPolicy compiles and validates a Starlark custom_code guardrail driver
// using ssrfPolicy when httpClient is nil.
func NewCustomCodeDriverWithPolicy(
	cfg guardrails.DriverConfig,
	ssrfPolicy *network.Policy,
	httpClient *http.Client,
) (*CustomCodeDriver, error) {
	effectiveCfg := resolveEffectiveConfig(cfg)
	code, err := extractCustomCodeSource(effectiveCfg)
	if err != nil {
		return nil, err
	}

	timeout := resolveExecutionTimeout(cfg.Definition, effectiveCfg)
	maxSteps := resolveMaxExecutionSteps(effectiveCfg)
	allowHTTP := resolveAllowHTTP(effectiveCfg)

	if httpClient == nil {
		if ssrfPolicy == nil {
			var policyErr error
			ssrfPolicy, policyErr = network.NewPolicy(config.OutboundSSRFConfig{})
			if policyErr != nil {
				return nil, fmt.Errorf("custom_code: build default network policy: %w", policyErr)
			}
		}
		httpClient = network.NewHTTPClient(ssrfPolicy)
	}

	guardrailName := CustomCodeProvider
	var guardrailID string
	var hooks []domain.GuardrailHook
	if cfg.Definition != nil {
		if name := strings.TrimSpace(cfg.Definition.Name); name != "" {
			guardrailName = name
		}
		guardrailID = strings.TrimSpace(cfg.Definition.ID)
		if len(cfg.Definition.EventHooks) > 0 {
			hooks = slices.Clone(cfg.Definition.EventHooks)
		}
	}

	d := &CustomCodeDriver{
		guardrailName: guardrailName,
		guardrailID:   guardrailID,
		hooks:         hooks,
		httpClient:    httpClient,
		allowHTTP:     allowHTTP,
		timeout:       timeout,
		maxSteps:      maxSteps,
		regexCache:    make(map[string]*regexp.Regexp),
	}

	predeclared := d.predeclared()
	_, prog, err := starlark.SourceProgramOptions(starlarkFileOptions, "custom_code.star", code, predeclared.Has)
	if err != nil {
		return nil, fmt.Errorf("custom_code: compile script: %w", err)
	}
	if prog.NumLoads() > 0 {
		return nil, fmt.Errorf("custom_code: load() statements are forbidden in sandboxed scripts")
	}

	// Validate module initialization and entry function signature without allowing network egress.
	valThread := &starlark.Thread{
		Name:  "custom_code_validate",
		Print: func(_ *starlark.Thread, _ string) {},
	}
	valThread.SetMaxExecutionSteps(maxSteps)
	globals, err := prog.Init(valThread, predeclared)
	if err != nil {
		return nil, fmt.Errorf("custom_code: initialize script: %w", err)
	}

	entryVal, ok := globals["apply_guardrail"]
	if !ok {
		return nil, fmt.Errorf("custom_code: script must define apply_guardrail(inputs, request_data, input_type)")
	}
	entryFn, ok := entryVal.(*starlark.Function)
	if !ok {
		return nil, fmt.Errorf("custom_code: apply_guardrail must be a function, got %s", entryVal.Type())
	}
	if err := validateEntrySignature(entryFn); err != nil {
		return nil, err
	}

	d.program = prog
	return d, nil
}

// Name returns the provider identifier ("custom_code").
func (d *CustomCodeDriver) Name() string {
	return CustomCodeProvider
}

// SupportedHooks returns the configured lifecycle hooks or all supported hooks by default.
func (d *CustomCodeDriver) SupportedHooks() []domain.GuardrailHook {
	if d != nil && len(d.hooks) > 0 {
		return slices.Clone(d.hooks)
	}
	return slices.Clone(defaultSupportedHooks)
}

// Evaluate executes apply_guardrail(inputs, request_data, input_type) under strict
// step and context-deadline bounds and converts the returned verdict into GuardrailEvalResult.
func (d *CustomCodeDriver) Evaluate(ctx context.Context, input *domain.GuardrailEvalInput) (*domain.GuardrailEvalResult, error) {
	if d == nil || d.program == nil {
		return nil, fmt.Errorf("custom_code: driver is not initialized")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	evalCtx, cancel := context.WithTimeout(ctx, d.timeout)
	defer cancel()

	thread := &starlark.Thread{
		Name:  "custom_code:" + d.guardrailName,
		Print: func(_ *starlark.Thread, _ string) {},
	}
	thread.SetMaxExecutionSteps(d.maxSteps)
	thread.SetLocal(threadCtxLocalKey, evalCtx)

	done := make(chan struct{})
	var watchWG sync.WaitGroup
	watchWG.Add(1)
	go func() {
		defer watchWG.Done()
		select {
		case <-evalCtx.Done():
			reason := "execution canceled"
			if errors.Is(evalCtx.Err(), context.DeadlineExceeded) {
				reason = "execution timeout exceeded"
			}
			thread.Cancel(reason)
		case <-done:
		}
	}()
	defer func() {
		close(done)
		watchWG.Wait()
	}()

	predeclared := d.predeclared()
	globals, err := d.program.Init(thread, predeclared)
	if err != nil {
		return nil, wrapStarlarkError("initialize script", evalCtx, err)
	}

	entryFn, ok := globals["apply_guardrail"].(*starlark.Function)
	if !ok {
		return nil, fmt.Errorf("custom_code: apply_guardrail is not a function")
	}

	inputsVal, reqDataVal, inputTypeVal, err := buildStarlarkArguments(input)
	if err != nil {
		return nil, fmt.Errorf("custom_code: marshal evaluation input: %w", err)
	}

	retVal, err := starlark.Call(thread, entryFn, starlark.Tuple{inputsVal, reqDataVal, inputTypeVal}, nil)
	if err != nil {
		return nil, wrapStarlarkError("execute apply_guardrail", evalCtx, err)
	}

	return d.parseVerdict(retVal)
}

func wrapStarlarkError(stage string, evalCtx context.Context, err error) error {
	if ctxErr := evalCtx.Err(); ctxErr != nil {
		return fmt.Errorf("custom_code: %s aborted (%v): %w", stage, ctxErr, err)
	}
	return fmt.Errorf("custom_code: %s failed: %w", stage, err)
}

func resolveEffectiveConfig(cfg guardrails.DriverConfig) map[string]any {
	if len(cfg.EffectiveConfig) > 0 {
		return cfg.EffectiveConfig
	}
	if cfg.Definition != nil && len(cfg.Definition.Config) > 0 {
		return cfg.Definition.Config
	}
	return nil
}

func extractCustomCodeSource(cfg map[string]any) (string, error) {
	for _, key := range []string{"custom_code", "code", "script"} {
		if raw, ok := cfg[key]; ok {
			src, ok := raw.(string)
			if !ok {
				return "", fmt.Errorf("custom_code: %s must be a string", key)
			}
			if strings.TrimSpace(src) == "" {
				return "", fmt.Errorf("custom_code: %s must not be empty", key)
			}
			return src, nil
		}
	}
	return "", fmt.Errorf("custom_code: missing required custom_code script in config")
}

func resolveExecutionTimeout(def *domain.GuardrailDefinition, cfg map[string]any) time.Duration {
	var ms int64
	if v, ok := extractInt64(cfg, "execution_timeout_ms"); ok && v > 0 {
		ms = v
	} else if v, ok := extractInt64(cfg, "timeout_ms"); ok && v > 0 {
		ms = v
	} else if def != nil && def.TimeoutMs > 0 {
		ms = int64(def.TimeoutMs)
	}
	if ms <= 0 {
		return defaultExecutionTimeout
	}
	d := time.Duration(ms) * time.Millisecond
	if d > maxExecutionTimeout {
		return maxExecutionTimeout
	}
	return d
}

func resolveMaxExecutionSteps(cfg map[string]any) uint64 {
	for _, key := range []string{"max_execution_steps", "max_steps"} {
		if v, ok := extractInt64(cfg, key); ok && v > 0 {
			steps := uint64(v)
			if steps > maxAllowedExecutionSteps {
				return maxAllowedExecutionSteps
			}
			return steps
		}
	}
	return defaultMaxExecutionSteps
}

func resolveAllowHTTP(cfg map[string]any) bool {
	if raw, ok := cfg["disable_http"].(bool); ok && raw {
		return false
	}
	if raw, ok := cfg["allow_http"].(bool); ok {
		return raw
	}
	return true
}

func extractInt64(cfg map[string]any, key string) (int64, bool) {
	if cfg == nil {
		return 0, false
	}
	raw, ok := cfg[key]
	if !ok || raw == nil {
		return 0, false
	}
	switch v := raw.(type) {
	case int:
		return int64(v), true
	case int32:
		return int64(v), true
	case int64:
		return v, true
	case uint:
		if v > math.MaxInt64 {
			return math.MaxInt64, true
		}
		return int64(v), true
	case uint64:
		if v > math.MaxInt64 {
			return math.MaxInt64, true
		}
		return int64(v), true
	case float64:
		if math.IsNaN(v) || math.IsInf(v, 0) {
			return 0, false
		}
		return int64(v), true
	default:
		return 0, false
	}
}

func validateEntrySignature(fn *starlark.Function) error {
	nonVariadic := fn.NumParams()
	if fn.HasVarargs() {
		nonVariadic--
	}
	if fn.HasKwargs() {
		nonVariadic--
	}
	positionalCount := nonVariadic - fn.NumKwonlyParams()
	for i := positionalCount; i < nonVariadic; i++ {
		if fn.ParamDefault(i) == nil {
			name, _ := fn.Param(i)
			return fmt.Errorf("custom_code: apply_guardrail keyword-only parameter %q must have a default value", name)
		}
	}
	minPositional := 0
	for i := 0; i < positionalCount; i++ {
		if fn.ParamDefault(i) == nil {
			minPositional++
		}
	}
	if minPositional > 3 {
		return fmt.Errorf("custom_code: apply_guardrail accepts at most 3 required positional parameters (inputs, request_data, input_type), got %d", minPositional)
	}
	if !fn.HasVarargs() && positionalCount < 3 {
		return fmt.Errorf("custom_code: apply_guardrail must accept 3 parameters (inputs, request_data, input_type), got %d", positionalCount)
	}
	return nil
}

func (d *CustomCodeDriver) predeclared() starlark.StringDict {
	return starlark.StringDict{
		"allow":         starlark.NewBuiltin("allow", builtinAllow),
		"block":         starlark.NewBuiltin("block", builtinBlock),
		"flag":          starlark.NewBuiltin("flag", builtinFlag),
		"modify":        starlark.NewBuiltin("modify", builtinModify),
		"regex_match":   starlark.NewBuiltin("regex_match", d.builtinRegexMatch),
		"regex_search":  starlark.NewBuiltin("regex_search", d.builtinRegexSearch),
		"regex_findall": starlark.NewBuiltin("regex_findall", d.builtinRegexFindAll),
		"regex_replace": starlark.NewBuiltin("regex_replace", d.builtinRegexReplace),
		"json_parse":    starlark.NewBuiltin("json_parse", builtinJSONParse),
		"json_dumps":    starlark.NewBuiltin("json_dumps", builtinJSONDumps),
		"sha256":        starlark.NewBuiltin("sha256", builtinSHA256),
		"lower":         starlark.NewBuiltin("lower", builtinLower),
		"contains":      starlark.NewBuiltin("contains", builtinContains),
		"http_get":      starlark.NewBuiltin("http_get", d.builtinHTTPGet),
		"http_post":     starlark.NewBuiltin("http_post", d.builtinHTTPPost),
	}
}

func builtinAllow(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var reason string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "reason?", &reason); err != nil {
		return nil, err
	}
	out := starlark.NewDict(2)
	_ = out.SetKey(starlark.String("action"), starlark.String(domain.GuardrailDecisionAllow))
	if reason != "" {
		_ = out.SetKey(starlark.String("reason"), starlark.String(reason))
	}
	return out, nil
}

func builtinBlock(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	return buildFindingDict(b.Name(), string(domain.GuardrailDecisionBlock), args, kwargs)
}

func builtinFlag(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	return buildFindingDict(b.Name(), string(domain.GuardrailDecisionFlag), args, kwargs)
}

func buildFindingDict(fnName, action string, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var (
		reason   string
		category string
		rule     string
		severity string
		score    starlark.Value = starlark.None
		details  starlark.Value = starlark.None
	)
	if err := starlark.UnpackArgs(
		fnName, args, kwargs,
		"reason?", &reason,
		"category?", &category,
		"rule?", &rule,
		"severity?", &severity,
		"score?", &score,
		"details?", &details,
	); err != nil {
		return nil, err
	}
	out := starlark.NewDict(7)
	_ = out.SetKey(starlark.String("action"), starlark.String(action))
	if reason != "" {
		_ = out.SetKey(starlark.String("reason"), starlark.String(reason))
	}
	if category != "" {
		_ = out.SetKey(starlark.String("category"), starlark.String(category))
	}
	if rule != "" {
		_ = out.SetKey(starlark.String("rule"), starlark.String(rule))
	}
	if severity != "" {
		_ = out.SetKey(starlark.String("severity"), starlark.String(severity))
	}
	if score != nil && score != starlark.None {
		_ = out.SetKey(starlark.String("score"), score)
	}
	if details != nil && details != starlark.None {
		_ = out.SetKey(starlark.String("details"), details)
	}
	return out, nil
}

func builtinModify(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var (
		textsVal     starlark.Value = starlark.None
		toolCallsVal starlark.Value = starlark.None
		messagesVal  starlark.Value = starlark.None
		reason       string
		category     string
		rule         string
		details      starlark.Value = starlark.None
	)
	if err := starlark.UnpackArgs(
		b.Name(), args, kwargs,
		"texts?", &textsVal,
		"tool_calls?", &toolCallsVal,
		"messages?", &messagesVal,
		"reason?", &reason,
		"category?", &category,
		"rule?", &rule,
		"details?", &details,
	); err != nil {
		return nil, err
	}
	out := starlark.NewDict(8)
	_ = out.SetKey(starlark.String("action"), starlark.String(domain.GuardrailDecisionModify))
	if textsVal != nil && textsVal != starlark.None {
		_ = out.SetKey(starlark.String("texts"), textsVal)
	}
	if toolCallsVal != nil && toolCallsVal != starlark.None {
		_ = out.SetKey(starlark.String("tool_calls"), toolCallsVal)
	}
	if messagesVal != nil && messagesVal != starlark.None {
		_ = out.SetKey(starlark.String("messages"), messagesVal)
	}
	if reason != "" {
		_ = out.SetKey(starlark.String("reason"), starlark.String(reason))
	}
	if category != "" {
		_ = out.SetKey(starlark.String("category"), starlark.String(category))
	}
	if rule != "" {
		_ = out.SetKey(starlark.String("rule"), starlark.String(rule))
	}
	if details != nil && details != starlark.None {
		_ = out.SetKey(starlark.String("details"), details)
	}
	return out, nil
}

func (d *CustomCodeDriver) compileRegex(pattern string) (*regexp.Regexp, error) {
	d.regexMu.RLock()
	re, ok := d.regexCache[pattern]
	d.regexMu.RUnlock()
	if ok {
		return re, nil
	}

	compiled, err := regexp.Compile(pattern)
	if err != nil {
		return nil, fmt.Errorf("invalid regex pattern %q: %w", pattern, err)
	}

	d.regexMu.Lock()
	if len(d.regexCache) >= maxRegexCacheEntries {
		clear(d.regexCache)
	}
	d.regexCache[pattern] = compiled
	d.regexMu.Unlock()
	return compiled, nil
}

func (d *CustomCodeDriver) builtinRegexMatch(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var text, pattern string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "text", &text, "pattern", &pattern); err != nil {
		return nil, err
	}
	re, err := d.compileRegex(pattern)
	if err != nil {
		return nil, err
	}
	return starlark.Bool(re.MatchString(text)), nil
}

func (d *CustomCodeDriver) builtinRegexSearch(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var text, pattern string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "text", &text, "pattern", &pattern); err != nil {
		return nil, err
	}
	re, err := d.compileRegex(pattern)
	if err != nil {
		return nil, err
	}
	loc := re.FindStringIndex(text)
	if loc == nil {
		return starlark.None, nil
	}
	return starlark.String(text[loc[0]:loc[1]]), nil
}

func (d *CustomCodeDriver) builtinRegexFindAll(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var text, pattern string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "text", &text, "pattern", &pattern); err != nil {
		return nil, err
	}
	re, err := d.compileRegex(pattern)
	if err != nil {
		return nil, err
	}
	matches := re.FindAllString(text, -1)
	items := make([]starlark.Value, len(matches))
	for i, m := range matches {
		items[i] = starlark.String(m)
	}
	return starlark.NewList(items), nil
}

func (d *CustomCodeDriver) builtinRegexReplace(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var text, pattern, repl string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "text", &text, "pattern", &pattern, "repl", &repl); err != nil {
		return nil, err
	}
	re, err := d.compileRegex(pattern)
	if err != nil {
		return nil, err
	}
	return starlark.String(re.ReplaceAllString(text, repl)), nil
}

func builtinJSONParse(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var raw string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "s", &raw); err != nil {
		return nil, err
	}
	return parseJSONToStarlark([]byte(raw))
}

func builtinJSONDumps(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var val starlark.Value
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "v", &val); err != nil {
		return nil, err
	}
	goVal, err := starlarkToGo(val, 0)
	if err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(goVal)
	if err != nil {
		return nil, fmt.Errorf("json_dumps: %w", err)
	}
	return starlark.String(encoded), nil
}

func builtinSHA256(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var s string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "s", &s); err != nil {
		return nil, err
	}
	sum := sha256.Sum256([]byte(s))
	return starlark.String(hex.EncodeToString(sum[:])), nil
}

func builtinLower(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var s string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "s", &s); err != nil {
		return nil, err
	}
	return starlark.String(strings.ToLower(s)), nil
}

func builtinContains(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var target, sub starlark.Value
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "s", &target, "sub", &sub); err != nil {
		return nil, err
	}
	switch v := target.(type) {
	case starlark.String:
		subStr, ok := sub.(starlark.String)
		if !ok {
			return nil, fmt.Errorf("contains: substring must be string, got %s", sub.Type())
		}
		return starlark.Bool(strings.Contains(string(v), string(subStr))), nil
	case *starlark.Dict:
		_, found, err := v.Get(sub)
		if err != nil {
			return nil, err
		}
		return starlark.Bool(found), nil
	case *starlark.Set:
		found, err := v.Has(sub)
		if err != nil {
			return nil, err
		}
		return starlark.Bool(found), nil
	case *starlark.List:
		return containsIterable(v, sub)
	case starlark.Tuple:
		return containsIterable(v, sub)
	default:
		return nil, fmt.Errorf("contains: expected string or collection, got %s", target.Type())
	}
}

func containsIterable(it starlark.Iterable, target starlark.Value) (starlark.Value, error) {
	iter := it.Iterate()
	defer iter.Done()
	var elem starlark.Value
	for iter.Next(&elem) {
		eq, err := starlark.Equal(elem, target)
		if err != nil {
			continue
		}
		if eq {
			return starlark.True, nil
		}
	}
	return starlark.False, nil
}

func (d *CustomCodeDriver) builtinHTTPGet(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var (
		rawURL     string
		headersVal starlark.Value = starlark.None
	)
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "url", &rawURL, "headers?", &headersVal); err != nil {
		return nil, err
	}
	return d.doHTTP(thread, http.MethodGet, rawURL, starlark.None, headersVal, starlark.None)
}

func (d *CustomCodeDriver) builtinHTTPPost(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var (
		rawURL     string
		jsonVal    starlark.Value = starlark.None
		headersVal starlark.Value = starlark.None
		bodyVal    starlark.Value = starlark.None
	)
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "url", &rawURL, "json?", &jsonVal, "headers?", &headersVal, "body?", &bodyVal); err != nil {
		return nil, err
	}
	return d.doHTTP(thread, http.MethodPost, rawURL, jsonVal, headersVal, bodyVal)
}

func (d *CustomCodeDriver) doHTTP(
	thread *starlark.Thread,
	method string,
	rawURL string,
	jsonVal starlark.Value,
	headersVal starlark.Value,
	bodyVal starlark.Value,
) (starlark.Value, error) {
	if !d.allowHTTP {
		return nil, fmt.Errorf("outbound HTTP calls are disabled by guardrail configuration")
	}
	ctx, ok := thread.Local(threadCtxLocalKey).(context.Context)
	if !ok || ctx == nil {
		return nil, fmt.Errorf("outbound HTTP calls are not permitted during module initialization")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	parsedURL, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || parsedURL.Scheme == "" || parsedURL.Host == "" {
		return nil, fmt.Errorf("invalid HTTP URL %q", rawURL)
	}

	var bodyReader io.Reader
	var defaultContentType string
	if jsonVal != nil && jsonVal != starlark.None {
		goPayload, convErr := starlarkToGo(jsonVal, 0)
		if convErr != nil {
			return nil, fmt.Errorf("encode json body: %w", convErr)
		}
		payloadBytes, marshalErr := json.Marshal(goPayload)
		if marshalErr != nil {
			return nil, fmt.Errorf("marshal json body: %w", marshalErr)
		}
		bodyReader = bytes.NewReader(payloadBytes)
		defaultContentType = "application/json"
	} else if bodyVal != nil && bodyVal != starlark.None {
		switch v := bodyVal.(type) {
		case starlark.String:
			bodyReader = strings.NewReader(string(v))
		case starlark.Bytes:
			bodyReader = strings.NewReader(string(v))
		default:
			return nil, fmt.Errorf("http body must be string or bytes, got %s", bodyVal.Type())
		}
	}

	req, err := http.NewRequestWithContext(ctx, method, parsedURL.String(), bodyReader)
	if err != nil {
		return nil, fmt.Errorf("construct HTTP request: %w", err)
	}
	if defaultContentType != "" {
		req.Header.Set("Content-Type", defaultContentType)
	}

	if headersVal != nil && headersVal != starlark.None {
		hdrDict, ok := headersVal.(*starlark.Dict)
		if !ok {
			return nil, fmt.Errorf("headers must be a dict, got %s", headersVal.Type())
		}
		for _, item := range hdrDict.Items() {
			kStr, okK := item[0].(starlark.String)
			vStr, okV := item[1].(starlark.String)
			if !okK || !okV {
				return nil, fmt.Errorf("header keys and values must be strings")
			}
			k := string(kStr)
			v := string(vStr)
			if strings.ContainsAny(k, "\r\n") || strings.ContainsAny(v, "\r\n") {
				return nil, fmt.Errorf("invalid header %q containing newline characters", k)
			}
			req.Header.Set(k, v)
		}
	}

	resp, err := d.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(io.LimitReader(resp.Body, maxHTTPResponseBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read HTTP response body: %w", err)
	}
	if int64(len(respBytes)) > maxHTTPResponseBytes {
		return nil, fmt.Errorf("HTTP response body exceeds %d byte limit", maxHTTPResponseBytes)
	}

	respHeaders := starlark.NewDict(len(resp.Header))
	for k, vals := range resp.Header {
		if len(vals) > 0 {
			_ = respHeaders.SetKey(starlark.String(strings.ToLower(k)), starlark.String(vals[0]))
		}
	}

	var parsedJSON starlark.Value = starlark.None
	if len(bytes.TrimSpace(respBytes)) > 0 {
		if jv, jErr := parseJSONToStarlark(respBytes); jErr == nil {
			parsedJSON = jv
		}
	}

	out := starlark.NewDict(5)
	_ = out.SetKey(starlark.String("status_code"), starlark.MakeInt(resp.StatusCode))
	_ = out.SetKey(starlark.String("ok"), starlark.Bool(resp.StatusCode >= 200 && resp.StatusCode < 300))
	_ = out.SetKey(starlark.String("body"), starlark.String(string(respBytes)))
	_ = out.SetKey(starlark.String("headers"), respHeaders)
	_ = out.SetKey(starlark.String("json"), parsedJSON)
	return out, nil
}

func buildStarlarkArguments(input *domain.GuardrailEvalInput) (starlark.Value, starlark.Value, starlark.Value, error) {
	if input == nil {
		input = &domain.GuardrailEvalInput{}
	}

	texts := make([]starlark.Value, len(input.Texts))
	for i, txt := range input.Texts {
		texts[i] = starlark.String(txt)
	}

	messagesVal, err := structSliceToStarlarkList(input.StructuredMessages)
	if err != nil {
		return nil, nil, nil, err
	}
	imagesVal, err := structSliceToStarlarkList(input.Images)
	if err != nil {
		return nil, nil, nil, err
	}
	toolsVal, err := structSliceToStarlarkList(input.Tools)
	if err != nil {
		return nil, nil, nil, err
	}
	toolCallsVal, err := structSliceToStarlarkList(input.ToolCalls)
	if err != nil {
		return nil, nil, nil, err
	}

	inputsDict := starlark.NewDict(5)
	_ = inputsDict.SetKey(starlark.String("texts"), starlark.NewList(texts))
	_ = inputsDict.SetKey(starlark.String("structured_messages"), messagesVal)
	_ = inputsDict.SetKey(starlark.String("images"), imagesVal)
	_ = inputsDict.SetKey(starlark.String("tools"), toolsVal)
	_ = inputsDict.SetKey(starlark.String("tool_calls"), toolCallsVal)

	tags := make([]starlark.Value, len(input.Tags))
	for i, tag := range input.Tags {
		tags[i] = starlark.String(tag)
	}

	headersDict := starlark.NewDict(len(input.RequestHeaders))
	for k, v := range input.RequestHeaders {
		if _, blocked := sensitiveHeaderNames[strings.ToLower(strings.TrimSpace(k))]; blocked {
			continue
		}
		_ = headersDict.SetKey(starlark.String(k), starlark.String(v))
	}

	metadataVal, err := goToStarlark(input.Metadata, 0)
	if err != nil {
		return nil, nil, nil, err
	}
	if metadataVal == nil || metadataVal == starlark.None {
		metadataVal = starlark.NewDict(0)
	}

	reqDataDict := starlark.NewDict(10)
	_ = reqDataDict.SetKey(starlark.String("model"), starlark.String(input.Model))
	_ = reqDataDict.SetKey(starlark.String("org_id"), starlark.String(input.OrgID))
	_ = reqDataDict.SetKey(starlark.String("team_id"), starlark.String(input.TeamID))
	_ = reqDataDict.SetKey(starlark.String("virtual_key_id"), starlark.String(input.VirtualKeyID))
	_ = reqDataDict.SetKey(starlark.String("end_user_id"), starlark.String(input.EndUserID))
	_ = reqDataDict.SetKey(starlark.String("request_id"), starlark.String(input.RequestID))
	_ = reqDataDict.SetKey(starlark.String("trace_id"), starlark.String(input.TraceID))
	_ = reqDataDict.SetKey(starlark.String("tags"), starlark.NewList(tags))
	_ = reqDataDict.SetKey(starlark.String("metadata"), metadataVal)
	_ = reqDataDict.SetKey(starlark.String("request_headers"), headersDict)

	inputType := resolveInputType(input)
	return inputsDict, reqDataDict, starlark.String(inputType), nil
}

func resolveInputType(input *domain.GuardrailEvalInput) string {
	if input == nil {
		return "request"
	}
	switch input.Hook {
	case domain.GuardrailHookPreMCPCall, domain.GuardrailHookDuringMCPCall, domain.GuardrailHookPostMCPCall:
		return "mcp_call"
	case domain.GuardrailHookPostCall:
		return "response"
	}
	if strings.EqualFold(input.Direction, domain.GuardrailDirectionOutput) {
		return "response"
	}
	return "request"
}

func structSliceToStarlarkList[T any](items []T) (starlark.Value, error) {
	if len(items) == 0 {
		return starlark.NewList(nil), nil
	}
	raw, err := json.Marshal(items)
	if err != nil {
		return nil, err
	}
	return parseJSONToStarlark(raw)
}

func parseJSONToStarlark(raw []byte) (starlark.Value, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var val any
	if err := dec.Decode(&val); err != nil {
		return nil, fmt.Errorf("json_parse: %w", err)
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		return nil, fmt.Errorf("json_parse: unexpected trailing JSON data")
	}
	return goToStarlark(val, 0)
}

func goToStarlark(v any, depth int) (starlark.Value, error) {
	if depth > maxJSONDepth {
		return nil, fmt.Errorf("value nesting exceeds maximum depth of %d", maxJSONDepth)
	}
	if v == nil {
		return starlark.None, nil
	}
	switch val := v.(type) {
	case bool:
		return starlark.Bool(val), nil
	case string:
		return starlark.String(val), nil
	case int:
		return starlark.MakeInt(val), nil
	case int64:
		return starlark.MakeInt64(val), nil
	case uint64:
		return starlark.MakeUint64(val), nil
	case float64:
		return starlark.Float(val), nil
	case json.Number:
		if i, err := val.Int64(); err == nil {
			return starlark.MakeInt64(i), nil
		}
		if f, err := val.Float64(); err == nil {
			return starlark.Float(f), nil
		}
		return starlark.String(val.String()), nil
	case []string:
		elems := make([]starlark.Value, len(val))
		for i, s := range val {
			elems[i] = starlark.String(s)
		}
		return starlark.NewList(elems), nil
	case []any:
		elems := make([]starlark.Value, len(val))
		for i, item := range val {
			sv, err := goToStarlark(item, depth+1)
			if err != nil {
				return nil, err
			}
			elems[i] = sv
		}
		return starlark.NewList(elems), nil
	case map[string]string:
		dict := starlark.NewDict(len(val))
		for k, item := range val {
			_ = dict.SetKey(starlark.String(k), starlark.String(item))
		}
		return dict, nil
	case map[string]any:
		dict := starlark.NewDict(len(val))
		for k, item := range val {
			sv, err := goToStarlark(item, depth+1)
			if err != nil {
				return nil, err
			}
			_ = dict.SetKey(starlark.String(k), sv)
		}
		return dict, nil
	default:
		encoded, err := json.Marshal(val)
		if err != nil {
			return nil, fmt.Errorf("unsupported value type %T: %w", v, err)
		}
		var normalized any
		dec := json.NewDecoder(bytes.NewReader(encoded))
		dec.UseNumber()
		if err := dec.Decode(&normalized); err != nil {
			return nil, err
		}
		return goToStarlark(normalized, depth+1)
	}
}

func starlarkToGo(v starlark.Value, depth int) (any, error) {
	if depth > maxJSONDepth {
		return nil, fmt.Errorf("value nesting exceeds maximum depth of %d", maxJSONDepth)
	}
	if v == nil || v == starlark.None {
		return nil, nil
	}
	switch val := v.(type) {
	case starlark.Bool:
		return bool(val), nil
	case starlark.Int:
		if i, ok := val.Int64(); ok {
			return i, nil
		}
		if u, ok := val.Uint64(); ok {
			return u, nil
		}
		return val.String(), nil
	case starlark.Float:
		f := float64(val)
		if math.IsNaN(f) || math.IsInf(f, 0) {
			return nil, fmt.Errorf("non-finite float cannot be serialized to JSON")
		}
		return f, nil
	case starlark.String:
		return string(val), nil
	case starlark.Bytes:
		return string(val), nil
	case *starlark.List:
		out := make([]any, 0, val.Len())
		for i := 0; i < val.Len(); i++ {
			gv, err := starlarkToGo(val.Index(i), depth+1)
			if err != nil {
				return nil, err
			}
			out = append(out, gv)
		}
		return out, nil
	case starlark.Tuple:
		out := make([]any, 0, len(val))
		for _, item := range val {
			gv, err := starlarkToGo(item, depth+1)
			if err != nil {
				return nil, err
			}
			out = append(out, gv)
		}
		return out, nil
	case *starlark.Set:
		out := make([]any, 0, val.Len())
		iter := val.Iterate()
		defer iter.Done()
		var elem starlark.Value
		for iter.Next(&elem) {
			gv, err := starlarkToGo(elem, depth+1)
			if err != nil {
				return nil, err
			}
			out = append(out, gv)
		}
		return out, nil
	case *starlark.Dict:
		out := make(map[string]any, val.Len())
		for _, item := range val.Items() {
			kStr, ok := item[0].(starlark.String)
			if !ok {
				return nil, fmt.Errorf("dict keys must be strings for JSON conversion, got %s", item[0].Type())
			}
			gv, err := starlarkToGo(item[1], depth+1)
			if err != nil {
				return nil, err
			}
			out[string(kStr)] = gv
		}
		return out, nil
	default:
		return nil, fmt.Errorf("unsupported Starlark value type %s", v.Type())
	}
}

func (d *CustomCodeDriver) parseVerdict(retVal starlark.Value) (*domain.GuardrailEvalResult, error) {
	base := &domain.GuardrailEvalResult{
		Decision:          domain.GuardrailDecisionAllow,
		AppliedGuardrails: []string{d.guardrailName},
	}
	if retVal == nil || retVal == starlark.None {
		return base, nil
	}

	dict, ok := retVal.(*starlark.Dict)
	if !ok {
		return nil, fmt.Errorf("custom_code: apply_guardrail must return a verdict dict or None, got %s", retVal.Type())
	}

	rawMap, err := starlarkToGo(dict, 0)
	if err != nil {
		return nil, fmt.Errorf("custom_code: decode verdict dict: %w", err)
	}
	verdictMap, ok := rawMap.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("custom_code: invalid verdict payload")
	}

	action := extractStringField(verdictMap, "action", "decision")
	action = strings.ToLower(strings.TrimSpace(action))
	if action == "" {
		action = string(domain.GuardrailDecisionAllow)
	}

	reason := extractStringField(verdictMap, "reason", "message")
	category := extractStringField(verdictMap, "category")
	rule := extractStringField(verdictMap, "rule")
	severity := extractStringField(verdictMap, "severity")
	score := extractScoreField(verdictMap)
	details, _ := verdictMap["details"].(map[string]any)

	switch action {
	case string(domain.GuardrailDecisionAllow):
		base.Decision = domain.GuardrailDecisionAllow
		return base, nil

	case string(domain.GuardrailDecisionBlock):
		if reason == "" {
			reason = fmt.Sprintf("Blocked by custom_code guardrail %q", d.guardrailName)
		}
		base.Decision = domain.GuardrailDecisionBlock
		base.ErrorMessage = reason
		base.Violations = []domain.GuardrailViolation{{
			GuardrailName: d.guardrailName,
			GuardrailID:   d.guardrailID,
			Provider:      CustomCodeProvider,
			Category:      category,
			Rule:          rule,
			Severity:      severity,
			Message:       reason,
			Score:         score,
			Action:        domain.GuardrailActionBlock,
			Decision:      domain.GuardrailDecisionBlock,
			Details:       details,
		}}
		return base, nil

	case string(domain.GuardrailDecisionFlag), string(domain.GuardrailActionAudit):
		if reason == "" {
			reason = fmt.Sprintf("Flagged by custom_code guardrail %q", d.guardrailName)
		}
		base.Decision = domain.GuardrailDecisionFlag
		base.Violations = []domain.GuardrailViolation{{
			GuardrailName: d.guardrailName,
			GuardrailID:   d.guardrailID,
			Provider:      CustomCodeProvider,
			Category:      category,
			Rule:          rule,
			Severity:      severity,
			Message:       reason,
			Score:         score,
			Action:        domain.GuardrailActionAudit,
			Decision:      domain.GuardrailDecisionFlag,
			Details:       details,
		}}
		return base, nil

	case string(domain.GuardrailDecisionModify), string(domain.GuardrailActionRedact):
		base.Decision = domain.GuardrailDecisionModify
		if rawTexts, ok := firstPresent(verdictMap, "texts", "modified_texts"); ok && rawTexts != nil {
			texts, err := parseStringSlice(rawTexts)
			if err != nil {
				return nil, fmt.Errorf("custom_code: invalid modify texts: %w", err)
			}
			base.ModifiedTexts = texts
		}
		if rawTCs, ok := firstPresent(verdictMap, "tool_calls", "modified_tool_calls"); ok && rawTCs != nil {
			tcs, err := parseToolCallsSlice(rawTCs)
			if err != nil {
				return nil, fmt.Errorf("custom_code: invalid modify tool_calls: %w", err)
			}
			base.ModifiedToolCalls = tcs
		}
		if rawMsgs, ok := firstPresent(verdictMap, "messages", "modified_messages"); ok && rawMsgs != nil {
			msgs, err := parseMessagesSlice(rawMsgs)
			if err != nil {
				return nil, fmt.Errorf("custom_code: invalid modify messages: %w", err)
			}
			base.ModifiedMessages = msgs
		}
		if reason != "" || category != "" || rule != "" {
			msg := reason
			if msg == "" {
				msg = fmt.Sprintf("Modified by custom_code guardrail %q", d.guardrailName)
			}
			base.Violations = []domain.GuardrailViolation{{
				GuardrailName: d.guardrailName,
				GuardrailID:   d.guardrailID,
				Provider:      CustomCodeProvider,
				Category:      category,
				Rule:          rule,
				Severity:      severity,
				Message:       msg,
				Score:         score,
				Action:        domain.GuardrailActionRedact,
				Decision:      domain.GuardrailDecisionModify,
				Details:       details,
			}}
		}
		return base, nil

	default:
		return nil, fmt.Errorf("custom_code: unsupported verdict action %q", action)
	}
}

func firstPresent(m map[string]any, keys ...string) (any, bool) {
	for _, k := range keys {
		if v, ok := m[k]; ok {
			return v, true
		}
	}
	return nil, false
}

func extractStringField(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if raw, ok := m[k]; ok && raw != nil {
			if s, ok := raw.(string); ok {
				return s
			}
		}
	}
	return ""
}

func extractScoreField(m map[string]any) *float64 {
	raw, ok := m["score"]
	if !ok || raw == nil {
		return nil
	}
	var f float64
	switch v := raw.(type) {
	case float64:
		f = v
	case int64:
		f = float64(v)
	case int:
		f = float64(v)
	default:
		return nil
	}
	return &f
}

func parseStringSlice(raw any) ([]string, error) {
	items, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("expected list of strings, got %T", raw)
	}
	out := make([]string, len(items))
	for i, item := range items {
		s, ok := item.(string)
		if !ok {
			return nil, fmt.Errorf("element %d must be string, got %T", i, item)
		}
		out[i] = s
	}
	return out, nil
}

func parseToolCallsSlice(raw any) ([]domain.CanonicalToolCall, error) {
	items, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("expected list of tool_calls, got %T", raw)
	}
	out := make([]domain.CanonicalToolCall, len(items))
	for i, item := range items {
		m, ok := item.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("tool_call[%d] must be a dict, got %T", i, item)
		}
		var tc domain.CanonicalToolCall
		if idxVal, ok := extractInt64(m, "index"); ok {
			idx := int(idxVal)
			tc.Index = &idx
		}
		tc.ID = extractStringField(m, "id")
		tc.Type = extractStringField(m, "type")
		if tc.Type == "" {
			tc.Type = "function"
		}
		if fnRaw, ok := m["function"]; ok && fnRaw != nil {
			fnMap, ok := fnRaw.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("tool_call[%d].function must be a dict, got %T", i, fnRaw)
			}
			tc.Function.Name = extractStringField(fnMap, "name")
			if argsRaw, exists := fnMap["arguments"]; exists && argsRaw != nil {
				switch a := argsRaw.(type) {
				case string:
					tc.Function.Arguments = a
				default:
					encoded, err := json.Marshal(a)
					if err != nil {
						return nil, fmt.Errorf("tool_call[%d].function.arguments: %w", i, err)
					}
					tc.Function.Arguments = string(encoded)
				}
			}
		} else {
			tc.Function.Name = extractStringField(m, "name")
		}
		out[i] = tc
	}
	return out, nil
}

func parseMessagesSlice(raw any) ([]domain.CanonicalMessage, error) {
	encoded, err := json.Marshal(raw)
	if err != nil {
		return nil, err
	}
	var msgs []domain.CanonicalMessage
	if err := json.Unmarshal(encoded, &msgs); err != nil {
		return nil, err
	}
	return msgs, nil
}
