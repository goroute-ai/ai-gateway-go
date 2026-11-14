package cache

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
)

func TestResponseCache_ComputeKeyCollisionResistance(t *testing.T) {
	rc := NewResponseCache(true, 100, nil)

	temp0 := 0.0
	temp7 := 0.7
	reqBase := &domain.CanonicalChatRequest{
		Model:       "gpt-4o",
		Temperature: &temp0,
		Messages: []domain.CanonicalMessage{
			{Role: "user", Content: "Tell me a joke"},
		},
	}

	keyBase := rc.ComputeKey("org-1", reqBase)

	// Different temperature must produce distinct key
	reqTemp := &domain.CanonicalChatRequest{
		Model:       "gpt-4o",
		Temperature: &temp7,
		Messages: []domain.CanonicalMessage{
			{Role: "user", Content: "Tell me a joke"},
		},
	}
	keyTemp := rc.ComputeKey("org-1", reqTemp)
	if keyTemp == keyBase {
		t.Fatalf("expected different cache key for different temperature")
	}

	// Different reasoning_effort must produce distinct key
	reqReasoning := &domain.CanonicalChatRequest{
		Model:           "gpt-4o",
		Temperature:     &temp0,
		ReasoningEffort: "high",
		Messages: []domain.CanonicalMessage{
			{Role: "user", Content: "Tell me a joke"},
		},
	}
	keyReasoning := rc.ComputeKey("org-1", reqReasoning)
	if keyReasoning == keyBase {
		t.Fatalf("expected different cache key for different reasoning_effort")
	}

	// Different top_p must produce distinct key
	topP := 0.8
	reqTopP := &domain.CanonicalChatRequest{
		Model:       "gpt-4o",
		Temperature: &temp0,
		TopP:        &topP,
		Messages: []domain.CanonicalMessage{
			{Role: "user", Content: "Tell me a joke"},
		},
	}
	keyTopP := rc.ComputeKey("org-1", reqTopP)
	if keyTopP == keyBase {
		t.Fatalf("expected different cache key for different top_p")
	}

	// Different org must produce distinct key
	keyOrg2 := rc.ComputeKey("org-2", reqBase)
	if keyOrg2 == keyBase {
		t.Fatalf("expected different cache key for different orgID")
	}
}

func TestResponseCacheMetricsTrackL1HitsAndEpochLookups(t *testing.T) {
	rc := NewResponseCache(true, time.Hour, nil)
	response := &domain.CanonicalChatResponse{Model: "model-a"}
	rc.SetWithMeta(context.Background(), "key-a", "org-a", response)
	if _, hit := rc.Get(context.Background(), "key-a"); !hit {
		t.Fatal("expected L1 cache hit")
	}
	metrics := rc.Metrics()
	if metrics.L1Hits != 1 || metrics.L1Misses != 0 {
		t.Fatalf("L1 hit metrics = %+v", metrics)
	}
	if metrics.EpochChecks != 2 {
		t.Fatalf("epoch checks = %d, want Set and Get checks", metrics.EpochChecks)
	}
}

func TestResponseCache_ComputeKeyIncludesAllCanonicalOutputFields(t *testing.T) {
	rc := NewResponseCache(true, 100, nil)
	temp := 0.0
	base := &domain.CanonicalChatRequest{
		Model: "model-a", Temperature: &temp,
		Messages: []domain.CanonicalMessage{{Role: "user", Content: "hello"}},
	}
	baseKey := rc.ComputeKey("org-1", base)
	cases := map[string]func(*domain.CanonicalChatRequest){
		"metadata":       func(r *domain.CanonicalChatRequest) { r.Metadata = map[string]string{"tenant_mode": "strict"} },
		"extra_params":   func(r *domain.CanonicalChatRequest) { r.ExtraParams = map[string]any{"seed": 41} },
		"stream_options": func(r *domain.CanonicalChatRequest) { r.StreamOptions = &domain.StreamOptions{IncludeUsage: true} },
		"gateway_extensions": func(r *domain.CanonicalChatRequest) {
			r.GoRouteExtensions = &domain.GoRouteExtensions{TaskID: "task-1"}
		},
		"request_id_is_ignored": func(r *domain.CanonicalChatRequest) { r.RequestID = "request-2" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			copy := *base
			mutate(&copy)
			key := rc.ComputeKey("org-1", &copy)
			if name == "request_id_is_ignored" {
				if key != baseKey {
					t.Fatal("request ID should not fragment equivalent cache entries")
				}
				return
			}
			if key == baseKey {
				t.Fatalf("expected %s to change the response cache key", name)
			}
		})
	}
}

func TestResponseCache_ComputeKeyDisablesCachingForUnencodableRequest(t *testing.T) {
	rc := NewResponseCache(true, 100, nil)
	key := rc.ComputeKey("org-1", &domain.CanonicalChatRequest{Model: "model-a", ExtraParams: map[string]any{"invalid": func() {}}})
	if key != "" {
		t.Fatalf("expected unencodable request to disable caching, got key %q", key)
	}
}

func TestResponseCache_L1CapacityEvictsLeastRecentlyUsedEntry(t *testing.T) {
	rc := NewResponseCacheWithL1Capacity(true, time.Hour, 2, nil)
	entry := cacheEntry{ExpiresAt: time.Now().Add(time.Hour)}
	rc.l1.store("a", entry)
	rc.l1.store("b", entry)
	if _, ok := rc.l1.load("a"); !ok { // Make a the most recently used entry.
		t.Fatal("expected a to be cached")
	}
	rc.l1.store("c", entry)
	if _, ok := rc.l1.load("a"); !ok {
		t.Fatal("least-recently-used eviction removed a")
	}
	if _, ok := rc.l1.load("b"); ok {
		t.Fatal("expected b to be evicted")
	}
	size, capacity, evicted := rc.L1Stats()
	if size != 2 || capacity != 2 || evicted != 1 {
		t.Fatalf("L1 stats = (%d,%d,%d), want (2,2,1)", size, capacity, evicted)
	}
}

func TestResponseCache_ComputeKeyAutoModelScope(t *testing.T) {
	rc := NewResponseCache(true, time.Hour, nil)
	req := &domain.CanonicalChatRequest{
		Model:    "auto",
		Messages: []domain.CanonicalMessage{{Role: "user", Content: "hi"}},
	}

	kTeam1ModelA := rc.ComputeKeyWithScope("org-1", "team-1", "gpt-4o", req)
	kTeam2ModelA := rc.ComputeKeyWithScope("org-1", "team-2", "gpt-4o", req)
	kTeam1ModelB := rc.ComputeKeyWithScope("org-1", "team-1", "claude-3-5-sonnet", req)

	if kTeam1ModelA == "" || kTeam2ModelA == "" || kTeam1ModelB == "" {
		t.Fatal("expected non-empty cache keys")
	}
	if kTeam1ModelA == kTeam2ModelA {
		t.Fatal("expected different TeamID to produce different cache keys when model == auto")
	}
	if kTeam1ModelA == kTeam1ModelB {
		t.Fatal("expected different effective model to produce different cache keys when model == auto")
	}
}

func TestResponseCache_CloneResponseDeepCopyRace(t *testing.T) {
	rc := NewResponseCache(true, time.Hour, nil)
	ctx := context.Background()
	key := rc.ComputeKey("org-1", &domain.CanonicalChatRequest{
		Model:    "gpt-4o",
		Messages: []domain.CanonicalMessage{{Role: "user", Content: "secret"}},
	})
	orig := &domain.CanonicalChatResponse{
		ID:       "resp-1",
		Model:    "gpt-4o",
		Metadata: map[string]string{"k": "v"},
		Choices: []domain.CanonicalChoice{
			{
				Index: 0,
				Message: domain.CanonicalMessage{
					Role:    "assistant",
					Content: "original secret",
					Parts: []domain.ContentPart{
						{Type: "text", Text: "part-1", ImageURL: &domain.ImageURL{URL: "https://example.com/a.png"}},
					},
					ToolCalls: []domain.CanonicalToolCall{
						{ID: "tc-1", Type: "function", Function: domain.CanonicalFunctionCall{Name: "fn", Arguments: `{"x":1}`}},
					},
				},
			},
		},
	}
	rc.SetWithMeta(ctx, key, "org-1", orig)

	// Mutate original after SetWithMeta; cached copy must remain untouched.
	orig.Choices[0].Message.Content = "mutated-orig"
	orig.Choices[0].Message.ToolCalls[0].Function.Arguments = "mutated-args"
	orig.Metadata["k"] = "mutated"

	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got, ok := rc.Get(ctx, key)
			if !ok {
				t.Errorf("expected cache hit")
				return
			}
			// Simulate SanitizeOutputStrict mutating the returned response concurrently.
			got.Choices[0].Message.Content = "[REDACTED]"
			got.Choices[0].Message.ToolCalls[0].Function.Arguments = "[REDACTED]"
			got.Choices[0].Message.Parts[0].ImageURL.URL = "[REDACTED]"
			got.Metadata["k"] = "[REDACTED]"
		}()
	}
	wg.Wait()

	final, ok := rc.Get(ctx, key)
	if !ok {
		t.Fatal("expected cache hit")
	}
	if final.Choices[0].Message.Content != "original secret" {
		t.Fatalf("cached content mutated: %q", final.Choices[0].Message.Content)
	}
	if final.Choices[0].Message.ToolCalls[0].Function.Arguments != `{"x":1}` {
		t.Fatalf("cached tool call mutated: %q", final.Choices[0].Message.ToolCalls[0].Function.Arguments)
	}
	if final.Choices[0].Message.Parts[0].ImageURL.URL != "https://example.com/a.png" {
		t.Fatalf("cached image URL mutated: %q", final.Choices[0].Message.Parts[0].ImageURL.URL)
	}
	if final.Metadata["k"] != "v" {
		t.Fatalf("cached metadata mutated: %q", final.Metadata["k"])
	}
}

func TestResponseCache_CompletionsAndEmbeddingsScopingAndL1(t *testing.T) {
	rc := NewResponseCache(true, time.Hour, nil)
	ctx := context.Background()

	temp0 := 0.0
	cmplReq := &domain.CanonicalCompletionRequest{
		Model:       "gpt-3.5-turbo-instruct",
		Temperature: &temp0,
		Prompt:      domain.CompletionPrompt{Strings: []string{"Hello world"}},
	}
	if !rc.IsCompletionCacheable(cmplReq, "") {
		t.Fatal("expected deterministic completion request to be cacheable")
	}
	if rc.IsCompletionCacheable(cmplReq, "no-cache") {
		t.Fatal("expected no-cache header to bypass completion cache")
	}

	k1 := rc.ComputeCompletionKeyWithScope("org-1", "team-1", "key:gpt-3.5-turbo-instruct", cmplReq)
	k2 := rc.ComputeCompletionKeyWithScope("org-2", "team-1", "key:gpt-3.5-turbo-instruct", cmplReq)
	k3 := rc.ComputeCompletionKeyWithScope("org-1", "team-2", "key:gpt-3.5-turbo-instruct", cmplReq)
	k4 := rc.ComputeCompletionKeyWithScope("org-1", "team-1", "key:other-model", cmplReq)
	if k1 == "" || k1 == k2 || k1 == k3 || k1 == k4 {
		t.Fatalf("expected distinct completion cache keys across org/team/effectiveModel scopes: %q %q %q %q", k1, k2, k3, k4)
	}

	cmplResp := &domain.CanonicalCompletionResponse{
		ID:       "cmpl-1",
		Model:    "gpt-3.5-turbo-instruct",
		Provider: domain.ProviderOpenAI,
		Choices:  []domain.CanonicalCompletionChoice{{Index: 0, Text: "cached completion"}},
	}
	rc.SetCompletionWithMeta(ctx, k1, "org-1", cmplResp)
	gotCmpl, hit := rc.GetCompletion(ctx, k1)
	if !hit || gotCmpl.Choices[0].Text != "cached completion" {
		t.Fatalf("expected completion L1 hit, got %+v hit=%v", gotCmpl, hit)
	}
	gotCmpl.Choices[0].Text = "mutated"
	gotCmpl2, hit := rc.GetCompletion(ctx, k1)
	if !hit || gotCmpl2.Choices[0].Text != "cached completion" {
		t.Fatalf("completion cache mutated in-place: %+v", gotCmpl2)
	}

	embReq := &domain.CanonicalEmbeddingRequest{
		Model: "text-embedding-3-small",
		Input: []string{"embed this"},
	}
	if !rc.IsEmbeddingCacheable(embReq, "") {
		t.Fatal("expected embedding request to be cacheable")
	}
	if rc.IsEmbeddingCacheable(embReq, "bypass") {
		t.Fatal("expected bypass header to disable embedding cache")
	}

	ek1 := rc.ComputeEmbeddingKeyWithScope("org-1", "team-1", "key:text-embedding-3-small", embReq)
	ek2 := rc.ComputeEmbeddingKeyWithScope("org-2", "team-1", "key:text-embedding-3-small", embReq)
	ek3 := rc.ComputeEmbeddingKeyWithScope("org-1", "team-2", "key:text-embedding-3-small", embReq)
	ek4 := rc.ComputeEmbeddingKeyWithScope("org-1", "team-1", "key:text-embedding-3-large", embReq)
	if ek1 == "" || ek1 == ek2 || ek1 == ek3 || ek1 == ek4 {
		t.Fatalf("expected distinct embedding cache keys across org/team/effectiveModel scopes: %q %q %q %q", ek1, ek2, ek3, ek4)
	}

	embResp := &domain.CanonicalEmbeddingResponse{
		Object:   "list",
		Model:    "text-embedding-3-small",
		Provider: domain.ProviderOpenAI,
		Data:     []domain.EmbeddingData{{Index: 0, Embedding: []float64{0.25, 0.75}}},
	}
	rc.SetEmbeddingWithMeta(ctx, ek1, "org-1", embResp)
	gotEmb, hit := rc.GetEmbedding(ctx, ek1)
	if !hit || len(gotEmb.Data) != 1 || gotEmb.Data[0].Embedding[0] != 0.25 {
		t.Fatalf("expected embedding L1 hit, got %+v hit=%v", gotEmb, hit)
	}
	gotEmb.Data[0].Embedding[0] = 99.0
	gotEmb2, hit := rc.GetEmbedding(ctx, ek1)
	if !hit || gotEmb2.Data[0].Embedding[0] != 0.25 {
		t.Fatalf("embedding cache mutated in-place: %+v", gotEmb2)
	}
}
