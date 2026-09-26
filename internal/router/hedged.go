package router

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/adapter"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
)

const (
	defaultHedgeConcurrency = 2
	maxHedgeConcurrency     = 3
)

var (
	errHedgedNoCandidates   = errors.New("hedged race: no candidate deployments")
	errHedgedNilInvoke      = errors.New("hedged race: invoke callback is nil")
	errHedgedNilResponse    = errors.New("hedged race: empty response")
	errHedgedNoStreamChunks = errors.New("hedged stream race: no valid stream chunks emitted")
	errHedgedAllFailed      = errors.New("hedged race: all candidates failed")
)

// HedgeConfig configures hedged fastest-response racing across candidate deployments.
type HedgeConfig struct {
	// MaxConcurrency caps the number of concurrent racers (default 2, clamped to [2, 3]).
	MaxConcurrency int
	// StaggerDelay, when > 0, launches candidate 0 first and only fires candidates 1..K-1
	// if no valid response arrives within StaggerDelay (or if candidate 0 fails sooner).
	StaggerDelay time.Duration
}

// ParseCommaSeparatedModels detects a comma-separated model list such as
// "fast,backup-claude" and returns trimmed non-empty aliases when at least two
// aliases are present; otherwise it returns nil.
func ParseCommaSeparatedModels(model string) []string {
	if !strings.Contains(model, ",") {
		return nil
	}
	parts := strings.Split(model, ",")
	aliases := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			aliases = append(aliases, trimmed)
		}
	}
	if len(aliases) < 2 {
		return nil
	}
	return aliases
}

type chatRaceResult struct {
	idx  int
	dep  *domain.Deployment
	resp *domain.CanonicalChatResponse
	err  error
}

// RaceChatAttempts races up to K = min(len(candidates), clamp(cfg.MaxConcurrency, 2, 3))
// non-streaming chat completion attempts concurrently (or staggered when cfg.StaggerDelay > 0).
// The first valid response wins and immediately cancels all slower attempts.
func RaceChatAttempts(
	ctx context.Context,
	candidates []*domain.Deployment,
	cfg HedgeConfig,
	invoke func(ctx context.Context, dep *domain.Deployment) (*domain.CanonicalChatResponse, error),
) (winner *domain.Deployment, resp *domain.CanonicalChatResponse, err error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if invoke == nil {
		return nil, nil, errHedgedNilInvoke
	}
	racers := filterNonNilDeployments(candidates)
	if len(racers) == 0 {
		return nil, nil, errHedgedNoCandidates
	}

	if len(racers) == 1 {
		resp, err := invoke(ctx, racers[0])
		if err != nil {
			return nil, nil, err
		}
		if resp == nil {
			return nil, nil, errHedgedNilResponse
		}
		return racers[0], resp, nil
	}

	k := minInt(len(racers), clampHedgeConcurrency(cfg.MaxConcurrency))
	racers = racers[:k]

	raceCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	results := make(chan chatRaceResult, k)
	errs := make([]error, k)
	launched := 0
	completed := 0

	launch := func(idx int) {
		dep := racers[idx]
		launched++
		go func() {
			r, callErr := invoke(raceCtx, dep)
			if callErr == nil && r == nil {
				callErr = errHedgedNilResponse
			}
			results <- chatRaceResult{idx: idx, dep: dep, resp: r, err: callErr}
		}()
	}

	launch(0)

	if cfg.StaggerDelay > 0 {
		timer := time.NewTimer(cfg.StaggerDelay)
		staggerDone := false
		for !staggerDone {
			select {
			case res := <-results:
				completed++
				if res.err == nil && res.resp != nil {
					timer.Stop()
					cancel()
					return res.dep, res.resp, nil
				}
				errs[res.idx] = res.err
				timer.Stop()
				staggerDone = true
			case <-timer.C:
				staggerDone = true
			case <-ctx.Done():
				timer.Stop()
				if dep, r, ok := drainWinningChatResult(results, errs, &completed); ok {
					cancel()
					return dep, r, nil
				}
				cancel()
				if err := selectMostInformativeError(errs); err != nil {
					return nil, nil, err
				}
				return nil, nil, ctx.Err()
			}
		}

		// If candidate 0 delivered a valid response concurrently with timer expiry, return it without firing backups.
		if dep, r, ok := drainWinningChatResult(results, errs, &completed); ok {
			cancel()
			return dep, r, nil
		}
		if ctx.Err() != nil {
			cancel()
			if err := selectMostInformativeError(errs); err != nil {
				return nil, nil, err
			}
			return nil, nil, ctx.Err()
		}
	}

	for i := 1; i < k; i++ {
		launch(i)
	}

	for completed < launched {
		select {
		case res := <-results:
			completed++
			if res.err == nil && res.resp != nil {
				cancel()
				return res.dep, res.resp, nil
			}
			errs[res.idx] = res.err
		default:
			select {
			case res := <-results:
				completed++
				if res.err == nil && res.resp != nil {
					cancel()
					return res.dep, res.resp, nil
				}
				errs[res.idx] = res.err
			case <-ctx.Done():
				cancel()
				if dep, r, ok := drainWinningChatResult(results, errs, &completed); ok {
					return dep, r, nil
				}
				if err := selectMostInformativeError(errs); err != nil {
					return nil, nil, err
				}
				return nil, nil, ctx.Err()
			}
		}
	}

	if err := selectMostInformativeError(errs); err != nil {
		return nil, nil, err
	}
	return nil, nil, errHedgedAllFailed
}

type streamRaceResult struct {
	idx   int
	usage *domain.TokenUsage
	err   error
}

// RaceStreamAttempts races up to K = min(len(candidates), clamp(cfg.MaxConcurrency, 2, 3))
// streaming completion attempts concurrently (or staggered when cfg.StaggerDelay > 0).
// Each racer buffers until it emits a valid non-empty chunk; the first racer to do so
// acquires the stream lock, invokes onSelected, cancels all other racers, drains its
// buffered first chunk and all subsequent chunks to onChunk, and returns its TokenUsage.
func RaceStreamAttempts(
	ctx context.Context,
	candidates []*domain.Deployment,
	cfg HedgeConfig,
	invoke func(ctx context.Context, dep *domain.Deployment, emit adapter.StreamChunkHandler) (*domain.TokenUsage, error),
	onChunk adapter.StreamChunkHandler,
	onSelected func(*domain.Deployment),
) (winner *domain.Deployment, usage *domain.TokenUsage, err error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if invoke == nil {
		return nil, nil, errHedgedNilInvoke
	}
	racers := filterNonNilDeployments(candidates)
	if len(racers) == 0 {
		return nil, nil, errHedgedNoCandidates
	}

	if len(racers) == 1 {
		selected := false
		emit := func(chunk *domain.CanonicalStreamChunk) error {
			if !isNonEmptyStreamChunk(chunk) {
				return nil
			}
			if !selected {
				selected = true
				if onSelected != nil {
					onSelected(racers[0])
				}
			}
			if onChunk != nil {
				return onChunk(chunk)
			}
			return nil
		}
		usage, err := invoke(ctx, racers[0], emit)
		if err != nil {
			if selected {
				return racers[0], usage, err
			}
			return nil, nil, err
		}
		return racers[0], usage, nil
	}

	k := minInt(len(racers), clampHedgeConcurrency(cfg.MaxConcurrency))
	racers = racers[:k]

	racerCtxs := make([]context.Context, k)
	racerCancels := make([]context.CancelFunc, k)
	for i := 0; i < k; i++ {
		racerCtxs[i], racerCancels[i] = context.WithCancel(ctx)
	}
	defer func() {
		for _, cancelFn := range racerCancels {
			cancelFn()
		}
	}()

	var (
		winnerOnce      sync.Once
		winnerIdx       atomic.Int32
		winnerClaimedCh = make(chan struct{})
	)
	winnerIdx.Store(-1)

	makeEmit := func(idx int, dep *domain.Deployment) adapter.StreamChunkHandler {
		var (
			mu       sync.Mutex
			isWinner bool
			preBuf   []*domain.CanonicalStreamChunk
		)
		return func(chunk *domain.CanonicalStreamChunk) error {
			mu.Lock()
			defer mu.Unlock()

			if isWinner {
				if chunk == nil {
					return nil
				}
				if onChunk != nil {
					return onChunk(chunk)
				}
				return nil
			}

			if w := winnerIdx.Load(); w >= 0 && int(w) != idx {
				return contextOrCanceledErr(racerCtxs[idx])
			}

			if !isNonEmptyStreamChunk(chunk) {
				return nil
			}

			// Hold the first valid chunk until this racer acquires winnerOnce.
			preBuf = append(preBuf, chunk)

			won := false
			winnerOnce.Do(func() {
				won = true
				winnerIdx.Store(int32(idx))
				for j, cancelFn := range racerCancels {
					if j != idx {
						cancelFn()
					}
				}
				close(winnerClaimedCh)
			})

			if !won {
				preBuf = nil
				return contextOrCanceledErr(racerCtxs[idx])
			}

			isWinner = true
			if onSelected != nil {
				onSelected(dep)
			}
			buffered := preBuf
			preBuf = nil
			for _, c := range buffered {
				if onChunk != nil {
					if emitErr := onChunk(c); emitErr != nil {
						return emitErr
					}
				}
			}
			return nil
		}
	}

	results := make(chan streamRaceResult, k)
	errs := make([]error, k)
	launched := 0
	completed := 0

	launch := func(idx int) {
		dep := racers[idx]
		emit := makeEmit(idx, dep)
		launched++
		go func() {
			u, callErr := invoke(racerCtxs[idx], dep, emit)
			results <- streamRaceResult{idx: idx, usage: u, err: callErr}
		}()
	}

	launch(0)

	if cfg.StaggerDelay > 0 {
		timer := time.NewTimer(cfg.StaggerDelay)
		staggerDone := false
		winnerActive := false

		for !staggerDone && !winnerActive {
			select {
			case <-winnerClaimedCh:
				timer.Stop()
				winnerActive = true
			case res := <-results:
				completed++
				if w := int(winnerIdx.Load()); w >= 0 && res.idx == w {
					timer.Stop()
					return racers[w], res.usage, res.err
				}
				timer.Stop()
				errs[res.idx] = normalizeStreamNoWinnerErr(res.err)
				staggerDone = true
			case <-timer.C:
				staggerDone = true
			case <-ctx.Done():
				timer.Stop()
				if w := int(winnerIdx.Load()); w >= 0 {
					return racers[w], nil, ctx.Err()
				}
				return nil, nil, ctx.Err()
			}
		}

		if !winnerActive && winnerIdx.Load() < 0 && ctx.Err() == nil {
			for i := 1; i < k; i++ {
				launch(i)
			}
		}
	} else {
		for i := 1; i < k; i++ {
			launch(i)
		}
	}

	for completed < launched {
		select {
		case res := <-results:
			if done, dep, u, callErr := handleStreamResult(res, racers, &winnerIdx, errs, &completed); done {
				return dep, u, callErr
			}
		default:
			select {
			case res := <-results:
				if done, dep, u, callErr := handleStreamResult(res, racers, &winnerIdx, errs, &completed); done {
					return dep, u, callErr
				}
			case <-ctx.Done():
				for {
					select {
					case res := <-results:
						if done, dep, u, callErr := handleStreamResult(res, racers, &winnerIdx, errs, &completed); done {
							return dep, u, callErr
						}
					default:
						if w := int(winnerIdx.Load()); w >= 0 {
							return racers[w], nil, ctx.Err()
						}
						if err := selectMostInformativeError(errs); err != nil {
							return nil, nil, err
						}
						return nil, nil, ctx.Err()
					}
				}
			}
		}
	}

	if err := selectMostInformativeError(errs); err != nil {
		return nil, nil, err
	}
	return nil, nil, errHedgedAllFailed
}

func handleStreamResult(
	res streamRaceResult,
	racers []*domain.Deployment,
	winnerIdx *atomic.Int32,
	errs []error,
	completed *int,
) (done bool, dep *domain.Deployment, usage *domain.TokenUsage, err error) {
	*completed++
	w := int(winnerIdx.Load())
	if w >= 0 && res.idx == w {
		return true, racers[w], res.usage, res.err
	}
	if w < 0 {
		errs[res.idx] = normalizeStreamNoWinnerErr(res.err)
	}
	return false, nil, nil, nil
}

func drainWinningChatResult(results <-chan chatRaceResult, errs []error, completed *int) (*domain.Deployment, *domain.CanonicalChatResponse, bool) {
	for {
		select {
		case res := <-results:
			*completed++
			if res.err == nil && res.resp != nil {
				return res.dep, res.resp, true
			}
			errs[res.idx] = res.err
		default:
			return nil, nil, false
		}
	}
}

func clampHedgeConcurrency(n int) int {
	if n < defaultHedgeConcurrency {
		return defaultHedgeConcurrency
	}
	if n > maxHedgeConcurrency {
		return maxHedgeConcurrency
	}
	return n
}

func filterNonNilDeployments(candidates []*domain.Deployment) []*domain.Deployment {
	if len(candidates) == 0 {
		return nil
	}
	out := make([]*domain.Deployment, 0, len(candidates))
	for _, dep := range candidates {
		if dep != nil {
			out = append(out, dep)
		}
	}
	return out
}

func isNonEmptyStreamChunk(chunk *domain.CanonicalStreamChunk) bool {
	if chunk == nil {
		return false
	}
	if chunk.Usage != nil {
		return true
	}
	for i := range chunk.Choices {
		c := &chunk.Choices[i]
		if c.Delta.Content != "" ||
			c.Delta.ReasoningContent != "" ||
			c.Delta.Role != "" ||
			len(c.Delta.ToolCalls) > 0 ||
			c.FinishReason != nil {
			return true
		}
	}
	return false
}

func selectMostInformativeError(errs []error) error {
	var (
		internalFallbackErr error
		deadlineErr         error
		canceledErr         error
	)
	for _, err := range errs {
		if err == nil {
			continue
		}
		if errors.Is(err, context.Canceled) {
			if canceledErr == nil {
				canceledErr = err
			}
			continue
		}
		if errors.Is(err, context.DeadlineExceeded) {
			if deadlineErr == nil {
				deadlineErr = err
			}
			continue
		}
		if errors.Is(err, errHedgedNilResponse) || errors.Is(err, errHedgedNoStreamChunks) {
			if internalFallbackErr == nil {
				internalFallbackErr = err
			}
			continue
		}
		return err
	}
	if internalFallbackErr != nil {
		return internalFallbackErr
	}
	if deadlineErr != nil {
		return deadlineErr
	}
	return canceledErr
}

func normalizeStreamNoWinnerErr(err error) error {
	if err != nil {
		return err
	}
	return errHedgedNoStreamChunks
}

func contextOrCanceledErr(ctx context.Context) error {
	if ctx != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	return context.Canceled
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
