package router

import (
	"context"
	"errors"
	"reflect"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/adapter"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
)

func makeHedgeDep(id string) *domain.Deployment {
	return &domain.Deployment{
		ID:             id,
		DeploymentName: id,
	}
}

func makeHedgeChatResp(id, content string) *domain.CanonicalChatResponse {
	return &domain.CanonicalChatResponse{
		ID:     id,
		Object: "chat.completion",
		Model:  "test-model",
		Choices: []domain.CanonicalChoice{
			{
				Index: 0,
				Message: domain.CanonicalMessage{
					Role:    "assistant",
					Content: content,
				},
				FinishReason: "stop",
			},
		},
	}
}

func makeHedgeStreamChunk(content string) *domain.CanonicalStreamChunk {
	return &domain.CanonicalStreamChunk{
		ID:     "chunk-1",
		Object: "chat.completion.chunk",
		Choices: []domain.CanonicalStreamChoice{
			{
				Index: 0,
				Delta: domain.CanonicalStreamDelta{
					Content: content,
				},
			},
		},
	}
}

func waitForGoroutinesToSettle(t *testing.T, baseline int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if runtime.NumGoroutine() <= baseline+1 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("goroutine leak detected: baseline=%d current=%d", baseline, runtime.NumGoroutine())
}

func TestHedgedParseCommaSeparatedModels(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{name: "empty", input: "", want: nil},
		{name: "single model", input: "gpt-4o", want: nil},
		{name: "single with whitespace", input: "  fast  ", want: nil},
		{name: "trailing comma only one alias", input: "fast,", want: nil},
		{name: "leading comma only one alias", input: ",fast", want: nil},
		{name: "only commas and spaces", input: " , , ", want: nil},
		{name: "two aliases", input: "fast,backup-claude", want: []string{"fast", "backup-claude"}},
		{name: "two aliases with spaces", input: " fast , backup-claude ", want: []string{"fast", "backup-claude"}},
		{name: "empty middle element skipped", input: "fast, , backup-claude", want: []string{"fast", "backup-claude"}},
		{name: "three aliases", input: "fast, coding, reasoning", want: []string{"fast", "coding", "reasoning"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ParseCommaSeparatedModels(tc.input)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("ParseCommaSeparatedModels(%q) = %#v, want %#v", tc.input, got, tc.want)
			}
		})
	}
}

func TestHedgedRaceChatAttempts_SimultaneousFastWinsAndCancelsSlow(t *testing.T) {
	baseline := runtime.NumGoroutine()

	slow := makeHedgeDep("slow")
	fast := makeHedgeDep("fast")

	slowStarted := make(chan struct{})
	slowCanceled := make(chan struct{})
	var slowDone atomic.Bool

	winner, resp, err := RaceChatAttempts(
		context.Background(),
		[]*domain.Deployment{slow, fast},
		HedgeConfig{MaxConcurrency: 2},
		func(ctx context.Context, dep *domain.Deployment) (*domain.CanonicalChatResponse, error) {
			if dep.ID == "slow" {
				close(slowStarted)
				<-ctx.Done()
				slowDone.Store(true)
				close(slowCanceled)
				return nil, ctx.Err()
			}
			<-slowStarted
			return makeHedgeChatResp("resp-fast", "fast-ok"), nil
		},
	)
	if err != nil {
		t.Fatalf("RaceChatAttempts failed: %v", err)
	}
	if winner == nil || winner.ID != "fast" {
		t.Fatalf("winner = %v, want fast", winner)
	}
	if resp == nil || resp.ID != "resp-fast" {
		t.Fatalf("resp = %v, want resp-fast", resp)
	}

	select {
	case <-slowCanceled:
	case <-time.After(time.Second):
		t.Fatal("expected slow candidate context to be canceled immediately after fast candidate won")
	}
	if !slowDone.Load() {
		t.Fatal("expected slow attempt to observe cancellation")
	}
	waitForGoroutinesToSettle(t, baseline)
}

func TestHedgedRaceChatAttempts_SingleCandidateZeroGoroutineOverhead(t *testing.T) {
	callerG := runtime.NumGoroutine()
	dep := makeHedgeDep("only")
	var invoked atomic.Int32

	winner, resp, err := RaceChatAttempts(
		context.Background(),
		[]*domain.Deployment{dep},
		HedgeConfig{MaxConcurrency: 3, StaggerDelay: 50 * time.Millisecond},
		func(ctx context.Context, d *domain.Deployment) (*domain.CanonicalChatResponse, error) {
			invoked.Add(1)
			if got := runtime.NumGoroutine(); got > callerG {
				t.Errorf("expected single-candidate fast path without spawning goroutines: before=%d during=%d", callerG, got)
			}
			return makeHedgeChatResp("only-resp", "ok"), nil
		},
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if winner != dep || resp == nil || resp.ID != "only-resp" {
		t.Fatalf("unexpected result: winner=%v resp=%v", winner, resp)
	}
	if invoked.Load() != 1 {
		t.Fatalf("invoked = %d, want 1", invoked.Load())
	}
}

func TestHedgedRaceChatAttempts_ConcurrencyClamping(t *testing.T) {
	candidates := []*domain.Deployment{
		makeHedgeDep("d0"),
		makeHedgeDep("d1"),
		makeHedgeDep("d2"),
		makeHedgeDep("d3"),
	}

	tests := []struct {
		name           string
		maxConcurrency int
		wantLaunched   int32
	}{
		{name: "default 0 clamps to 2", maxConcurrency: 0, wantLaunched: 2},
		{name: "1 clamps to 2", maxConcurrency: 1, wantLaunched: 2},
		{name: "explicit 3", maxConcurrency: 3, wantLaunched: 3},
		{name: "5 caps at 3", maxConcurrency: 5, wantLaunched: 3},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var launched atomic.Int32
			allEntered := make(chan struct{})

			_, _, err := RaceChatAttempts(
				context.Background(),
				candidates,
				HedgeConfig{MaxConcurrency: tc.maxConcurrency},
				func(ctx context.Context, dep *domain.Deployment) (*domain.CanonicalChatResponse, error) {
					if launched.Add(1) == tc.wantLaunched {
						close(allEntered)
					}
					select {
					case <-allEntered:
					case <-time.After(500 * time.Millisecond):
					}
					if dep.ID == "d1" {
						return makeHedgeChatResp("ok", "ok"), nil
					}
					<-ctx.Done()
					return nil, ctx.Err()
				},
			)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got := launched.Load(); got != tc.wantLaunched {
				t.Fatalf("launched = %d, want %d", got, tc.wantLaunched)
			}
		})
	}
}

func TestHedgedRaceChatAttempts_StaggeredPrimaryFastSkipsSecondary(t *testing.T) {
	baseline := runtime.NumGoroutine()

	primary := makeHedgeDep("primary")
	secondary := makeHedgeDep("secondary")

	var launched atomic.Int32
	var secondaryCalled atomic.Bool

	winner, resp, err := RaceChatAttempts(
		context.Background(),
		[]*domain.Deployment{primary, secondary},
		HedgeConfig{MaxConcurrency: 2, StaggerDelay: 120 * time.Millisecond},
		func(ctx context.Context, dep *domain.Deployment) (*domain.CanonicalChatResponse, error) {
			launched.Add(1)
			if dep.ID == "secondary" {
				secondaryCalled.Store(true)
				return makeHedgeChatResp("sec", "sec"), nil
			}
			time.Sleep(5 * time.Millisecond)
			return makeHedgeChatResp("pri", "pri"), nil
		},
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if winner == nil || winner.ID != "primary" || resp.ID != "pri" {
		t.Fatalf("unexpected winner=%v resp=%v", winner, resp)
	}
	// Wait past StaggerDelay to ensure secondary was never launched.
	time.Sleep(150 * time.Millisecond)
	if secondaryCalled.Load() || launched.Load() != 1 {
		t.Fatalf("expected only primary to run (launched=%d secondaryCalled=%v)", launched.Load(), secondaryCalled.Load())
	}
	waitForGoroutinesToSettle(t, baseline)
}

func TestHedgedRaceChatAttempts_StaggeredPrimaryStallsSecondaryWins(t *testing.T) {
	baseline := runtime.NumGoroutine()

	primary := makeHedgeDep("primary")
	secondary := makeHedgeDep("secondary")

	primaryCanceled := make(chan struct{})

	start := time.Now()
	winner, resp, err := RaceChatAttempts(
		context.Background(),
		[]*domain.Deployment{primary, secondary},
		HedgeConfig{MaxConcurrency: 2, StaggerDelay: 25 * time.Millisecond},
		func(ctx context.Context, dep *domain.Deployment) (*domain.CanonicalChatResponse, error) {
			if dep.ID == "primary" {
				<-ctx.Done()
				close(primaryCanceled)
				return nil, ctx.Err()
			}
			return makeHedgeChatResp("sec-win", "fast-backup"), nil
		},
	)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if winner == nil || winner.ID != "secondary" || resp.ID != "sec-win" {
		t.Fatalf("winner=%v resp=%v, want secondary/sec-win", winner, resp)
	}
	if elapsed < 20*time.Millisecond {
		t.Fatalf("expected stagger delay before secondary launch, elapsed=%v", elapsed)
	}

	select {
	case <-primaryCanceled:
	case <-time.After(time.Second):
		t.Fatal("expected stalled primary to be canceled after secondary won")
	}
	waitForGoroutinesToSettle(t, baseline)
}

func TestHedgedRaceChatAttempts_StaggeredPrimaryFastFailLaunchesSecondaryImmediately(t *testing.T) {
	baseline := runtime.NumGoroutine()

	primary := makeHedgeDep("primary")
	secondary := makeHedgeDep("secondary")

	primaryErr := errors.New("upstream 503")
	start := time.Now()
	winner, resp, err := RaceChatAttempts(
		context.Background(),
		[]*domain.Deployment{primary, secondary},
		HedgeConfig{MaxConcurrency: 2, StaggerDelay: 800 * time.Millisecond},
		func(ctx context.Context, dep *domain.Deployment) (*domain.CanonicalChatResponse, error) {
			if dep.ID == "primary" {
				return nil, primaryErr
			}
			return makeHedgeChatResp("sec-fast", "recovered"), nil
		},
	)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if winner == nil || winner.ID != "secondary" || resp.ID != "sec-fast" {
		t.Fatalf("winner=%v resp=%v, want secondary", winner, resp)
	}
	if elapsed >= 250*time.Millisecond {
		t.Fatalf("expected immediate secondary launch on primary fast-fail, took %v", elapsed)
	}
	waitForGoroutinesToSettle(t, baseline)
}

func TestHedgedRaceChatAttempts_AllFailPrefersInformativeError(t *testing.T) {
	d0 := makeHedgeDep("d0")
	d1 := makeHedgeDep("d1")
	d2 := makeHedgeDep("d2")

	upstreamErr := errors.New("upstream rate limited")
	winner, resp, err := RaceChatAttempts(
		context.Background(),
		[]*domain.Deployment{d0, d1, d2},
		HedgeConfig{MaxConcurrency: 3},
		func(ctx context.Context, dep *domain.Deployment) (*domain.CanonicalChatResponse, error) {
			switch dep.ID {
			case "d0":
				return nil, context.Canceled
			case "d1":
				return nil, nil // empty response treated as failure
			default:
				return nil, upstreamErr
			}
		},
	)
	if winner != nil || resp != nil {
		t.Fatalf("expected nil winner and resp on total failure, got winner=%v resp=%v", winner, resp)
	}
	if !errors.Is(err, upstreamErr) {
		t.Fatalf("err = %v, want %v (non-context-canceled error)", err, upstreamErr)
	}
}

func TestHedgedRaceStreamAttempts_FirstValidChunkWinsAndCancelsSlower(t *testing.T) {
	baseline := runtime.NumGoroutine()

	slow := makeHedgeDep("slow")
	fast := makeHedgeDep("fast")

	slowStarted := make(chan struct{})
	slowCanceled := make(chan struct{})

	var (
		mu            sync.Mutex
		selectedIDs   []string
		emittedChunks []string
		wantUsage     = &domain.TokenUsage{PromptTokens: 10, CompletionTokens: 6, TotalTokens: 16}
	)

	winner, usage, err := RaceStreamAttempts(
		context.Background(),
		[]*domain.Deployment{slow, fast},
		HedgeConfig{MaxConcurrency: 2},
		func(ctx context.Context, dep *domain.Deployment, emit adapter.StreamChunkHandler) (*domain.TokenUsage, error) {
			if dep.ID == "slow" {
				// Emit an empty chunk first; must NOT claim winner lock or emit downstream.
				if err := emit(&domain.CanonicalStreamChunk{}); err != nil {
					return nil, err
				}
				close(slowStarted)
				<-ctx.Done()
				// Even if slow attempts to emit after cancellation, it must be rejected.
				_ = emit(makeHedgeStreamChunk("slow-should-never-emit"))
				close(slowCanceled)
				return nil, ctx.Err()
			}

			<-slowStarted
			// Emit empty chunk first, then valid chunks.
			if err := emit(&domain.CanonicalStreamChunk{}); err != nil {
				return nil, err
			}
			for _, tok := range []string{"hello ", "world", "!"} {
				if err := emit(makeHedgeStreamChunk(tok)); err != nil {
					return nil, err
				}
			}
			return wantUsage, nil
		},
		func(chunk *domain.CanonicalStreamChunk) error {
			mu.Lock()
			defer mu.Unlock()
			if len(chunk.Choices) > 0 {
				emittedChunks = append(emittedChunks, chunk.Choices[0].Delta.Content)
			}
			return nil
		},
		func(dep *domain.Deployment) {
			mu.Lock()
			defer mu.Unlock()
			selectedIDs = append(selectedIDs, dep.ID)
		},
	)
	if err != nil {
		t.Fatalf("RaceStreamAttempts failed: %v", err)
	}
	if winner == nil || winner.ID != "fast" {
		t.Fatalf("winner = %v, want fast", winner)
	}
	if !reflect.DeepEqual(usage, wantUsage) {
		t.Fatalf("usage = %+v, want %+v", usage, wantUsage)
	}

	select {
	case <-slowCanceled:
	case <-time.After(time.Second):
		t.Fatal("expected slow stream racer to be canceled immediately")
	}

	mu.Lock()
	defer mu.Unlock()
	if !reflect.DeepEqual(selectedIDs, []string{"fast"}) {
		t.Fatalf("selectedIDs = %v, want [fast]", selectedIDs)
	}
	if !reflect.DeepEqual(emittedChunks, []string{"hello ", "world", "!"}) {
		t.Fatalf("emittedChunks = %v, want [hello  world !]", emittedChunks)
	}
	waitForGoroutinesToSettle(t, baseline)
}

func TestHedgedRaceStreamAttempts_StaggeredPrimaryFastSkipsSecondary(t *testing.T) {
	baseline := runtime.NumGoroutine()

	primary := makeHedgeDep("primary")
	secondary := makeHedgeDep("secondary")

	var secondaryCalled atomic.Bool
	var chunks []string
	var selected atomic.Int32

	winner, usage, err := RaceStreamAttempts(
		context.Background(),
		[]*domain.Deployment{primary, secondary},
		HedgeConfig{MaxConcurrency: 2, StaggerDelay: 120 * time.Millisecond},
		func(ctx context.Context, dep *domain.Deployment, emit adapter.StreamChunkHandler) (*domain.TokenUsage, error) {
			if dep.ID == "secondary" {
				secondaryCalled.Store(true)
				return nil, errors.New("should not run")
			}
			if err := emit(makeHedgeStreamChunk("first")); err != nil {
				return nil, err
			}
			time.Sleep(150 * time.Millisecond) // streaming continues past StaggerDelay after claiming lock
			if err := emit(makeHedgeStreamChunk("second")); err != nil {
				return nil, err
			}
			return &domain.TokenUsage{TotalTokens: 4}, nil
		},
		func(chunk *domain.CanonicalStreamChunk) error {
			chunks = append(chunks, chunk.Choices[0].Delta.Content)
			return nil
		},
		func(dep *domain.Deployment) {
			selected.Add(1)
		},
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if winner == nil || winner.ID != "primary" || usage == nil || usage.TotalTokens != 4 {
		t.Fatalf("unexpected result: winner=%v usage=%v", winner, usage)
	}
	if secondaryCalled.Load() {
		t.Fatal("expected secondary stream racer never to be launched when primary wins before StaggerDelay")
	}
	if selected.Load() != 1 || !reflect.DeepEqual(chunks, []string{"first", "second"}) {
		t.Fatalf("selected=%d chunks=%v", selected.Load(), chunks)
	}
	waitForGoroutinesToSettle(t, baseline)
}

func TestHedgedRaceStreamAttempts_StaggeredPrimaryStallsSecondaryWins(t *testing.T) {
	baseline := runtime.NumGoroutine()

	primary := makeHedgeDep("primary")
	secondary := makeHedgeDep("secondary")
	primaryCanceled := make(chan struct{})
	var chunks []string

	winner, usage, err := RaceStreamAttempts(
		context.Background(),
		[]*domain.Deployment{primary, secondary},
		HedgeConfig{MaxConcurrency: 2, StaggerDelay: 25 * time.Millisecond},
		func(ctx context.Context, dep *domain.Deployment, emit adapter.StreamChunkHandler) (*domain.TokenUsage, error) {
			if dep.ID == "primary" {
				<-ctx.Done()
				close(primaryCanceled)
				return nil, ctx.Err()
			}
			if err := emit(makeHedgeStreamChunk("backup-chunk")); err != nil {
				return nil, err
			}
			return &domain.TokenUsage{TotalTokens: 9}, nil
		},
		func(chunk *domain.CanonicalStreamChunk) error {
			chunks = append(chunks, chunk.Choices[0].Delta.Content)
			return nil
		},
		nil,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if winner == nil || winner.ID != "secondary" || usage.TotalTokens != 9 {
		t.Fatalf("winner=%v usage=%v", winner, usage)
	}
	if !reflect.DeepEqual(chunks, []string{"backup-chunk"}) {
		t.Fatalf("chunks=%v, want [backup-chunk]", chunks)
	}
	select {
	case <-primaryCanceled:
	case <-time.After(time.Second):
		t.Fatal("expected stalled primary stream to be canceled")
	}
	waitForGoroutinesToSettle(t, baseline)
}

func TestHedgedRaceStreamAttempts_StaggeredPrimaryFastFailLaunchesSecondaryImmediately(t *testing.T) {
	baseline := runtime.NumGoroutine()

	primary := makeHedgeDep("primary")
	secondary := makeHedgeDep("secondary")
	var chunks []string

	start := time.Now()
	winner, usage, err := RaceStreamAttempts(
		context.Background(),
		[]*domain.Deployment{primary, secondary},
		HedgeConfig{MaxConcurrency: 2, StaggerDelay: 800 * time.Millisecond},
		func(ctx context.Context, dep *domain.Deployment, emit adapter.StreamChunkHandler) (*domain.TokenUsage, error) {
			if dep.ID == "primary" {
				return nil, errors.New("connection refused")
			}
			if err := emit(makeHedgeStreamChunk("immediate-backup")); err != nil {
				return nil, err
			}
			return &domain.TokenUsage{TotalTokens: 3}, nil
		},
		func(chunk *domain.CanonicalStreamChunk) error {
			chunks = append(chunks, chunk.Choices[0].Delta.Content)
			return nil
		},
		nil,
	)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if winner == nil || winner.ID != "secondary" || usage.TotalTokens != 3 {
		t.Fatalf("winner=%v usage=%v", winner, usage)
	}
	if elapsed >= 250*time.Millisecond {
		t.Fatalf("expected immediate secondary launch after fast-fail, took %v", elapsed)
	}
	if !reflect.DeepEqual(chunks, []string{"immediate-backup"}) {
		t.Fatalf("chunks=%v, want [immediate-backup]", chunks)
	}
	waitForGoroutinesToSettle(t, baseline)
}

func TestHedgedRaceStreamAttempts_AllFailOrZeroChunks(t *testing.T) {
	d0 := makeHedgeDep("d0")
	d1 := makeHedgeDep("d1")

	var selectedCalls atomic.Int32
	var chunkCalls atomic.Int32
	wantErr := errors.New("provider stream error")

	winner, usage, err := RaceStreamAttempts(
		context.Background(),
		[]*domain.Deployment{d0, d1},
		HedgeConfig{MaxConcurrency: 2},
		func(ctx context.Context, dep *domain.Deployment, emit adapter.StreamChunkHandler) (*domain.TokenUsage, error) {
			if dep.ID == "d0" {
				// Completes without emitting any valid chunks.
				_ = emit(&domain.CanonicalStreamChunk{})
				return &domain.TokenUsage{}, nil
			}
			return nil, wantErr
		},
		func(chunk *domain.CanonicalStreamChunk) error {
			chunkCalls.Add(1)
			return nil
		},
		func(dep *domain.Deployment) {
			selectedCalls.Add(1)
		},
	)
	if winner != nil || usage != nil {
		t.Fatalf("expected nil winner and usage, got winner=%v usage=%v", winner, usage)
	}
	if err == nil {
		t.Fatal("expected error when no stream racer emits valid chunks")
	}
	if selectedCalls.Load() != 0 || chunkCalls.Load() != 0 {
		t.Fatalf("expected no selection or chunk emission, selected=%d chunks=%d", selectedCalls.Load(), chunkCalls.Load())
	}
}

func TestHedgedRaceStreamAttempts_SimultaneousFirstChunkCollisionRaceFree(t *testing.T) {
	baseline := runtime.NumGoroutine()
	candidates := []*domain.Deployment{
		makeHedgeDep("r0"),
		makeHedgeDep("r1"),
		makeHedgeDep("r2"),
	}

	for iter := 0; iter < 30; iter++ {
		startGate := make(chan struct{})
		var readyCount atomic.Int32
		var selectedCount atomic.Int32
		var mu sync.Mutex
		var chunks []string

		winner, _, err := RaceStreamAttempts(
			context.Background(),
			candidates,
			HedgeConfig{MaxConcurrency: 3},
			func(ctx context.Context, dep *domain.Deployment, emit adapter.StreamChunkHandler) (*domain.TokenUsage, error) {
				if readyCount.Add(1) == 3 {
					close(startGate)
				} else {
					<-startGate
				}
				if err := emit(makeHedgeStreamChunk(dep.ID + "-1")); err != nil {
					return nil, err
				}
				if err := emit(makeHedgeStreamChunk(dep.ID + "-2")); err != nil {
					return nil, err
				}
				return &domain.TokenUsage{TotalTokens: 2}, nil
			},
			func(chunk *domain.CanonicalStreamChunk) error {
				mu.Lock()
				defer mu.Unlock()
				chunks = append(chunks, chunk.Choices[0].Delta.Content)
				return nil
			},
			func(dep *domain.Deployment) {
				selectedCount.Add(1)
			},
		)
		if err != nil {
			t.Fatalf("iter %d unexpected error: %v", iter, err)
		}
		if winner == nil {
			t.Fatalf("iter %d expected non-nil winner", iter)
		}
		if got := selectedCount.Load(); got != 1 {
			t.Fatalf("iter %d selectedCount = %d, want 1", iter, got)
		}
		wantChunks := []string{winner.ID + "-1", winner.ID + "-2"}
		if !reflect.DeepEqual(chunks, wantChunks) {
			t.Fatalf("iter %d chunks = %v, want %v (must not interleave)", iter, chunks, wantChunks)
		}
	}
	waitForGoroutinesToSettle(t, baseline)
}
