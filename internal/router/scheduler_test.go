package router

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
)

func waitForQueuedCount(t *testing.T, s *PriorityScheduler, want int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if s.Stats().Queued == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("timed out waiting for queued count %d (got %d)", want, s.Stats().Queued)
}

func TestPriorityScheduler_PassThrough(t *testing.T) {
	cases := []struct {
		name string
		s    *PriorityScheduler
	}{
		{name: "nil_scheduler", s: nil},
		{name: "zero_max_concurrent", s: NewPriorityScheduler(0, 0, time.Second)},
		{name: "negative_max_concurrent", s: NewPriorityScheduler(-1, 1, time.Second)},
		{name: "disabled_config", s: NewPrioritySchedulerWithConfig(SchedulerConfig{
			Enabled:       false,
			MaxConcurrent: 1,
			MaxQueueDepth: 1,
		})},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var releases []func()
			for i := 0; i < 16; i++ {
				rel, err := tc.s.Acquire(context.Background(), i)
				if err != nil {
					t.Fatalf("Acquire(%d) unexpected error: %v", i, err)
				}
				releases = append(releases, rel)
			}
			if tc.s != nil {
				st := tc.s.Stats()
				if st.Active != 0 || st.Queued != 0 || st.Rejected != 0 || st.TimedOut != 0 {
					t.Fatalf("expected zero stats in pass-through mode, got %+v", st)
				}
			}
			for _, rel := range releases {
				rel()
				rel() // idempotent
			}
		})
	}
}

func TestPriorityScheduler_PriorityOrdering(t *testing.T) {
	s := NewPriorityScheduler(1, 10, 5*time.Second)

	holdRelease, err := s.Acquire(context.Background(), 0)
	if err != nil {
		t.Fatalf("initial Acquire failed: %v", err)
	}

	type item struct {
		id       string
		priority int
	}
	// Enqueue in non-priority order; negative priority should normalize to 0.
	items := []item{
		{id: "p5", priority: 5},
		{id: "p1", priority: 1},
		{id: "p0-first", priority: 0},
		{id: "p3", priority: 3},
		{id: "p-neg-second", priority: -4},
	}

	orderCh := make(chan string, len(items))
	var wg sync.WaitGroup

	for i, it := range items {
		wg.Add(1)
		go func(it item) {
			defer wg.Done()
			rel, err := s.Acquire(context.Background(), it.priority)
			if err != nil {
				t.Errorf("waiter %s Acquire failed: %v", it.id, err)
				return
			}
			orderCh <- it.id
			rel()
		}(it)
		// Wait after each launch so seq ordering reflects items slice order.
		waitForQueuedCount(t, s, i+1)
	}

	// Release the held slot to start draining the priority heap one by one.
	holdRelease()
	wg.Wait()
	close(orderCh)

	var got []string
	for id := range orderCh {
		got = append(got, id)
	}
	want := []string{"p0-first", "p-neg-second", "p1", "p3", "p5"}
	if len(got) != len(want) {
		t.Fatalf("acquired count = %d, want %d (got %v)", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("wake order = %v, want %v", got, want)
		}
	}

	st := s.Stats()
	if st.Active != 0 || st.Queued != 0 {
		t.Fatalf("expected clean drained stats, got %+v", st)
	}
}

func TestPriorityScheduler_FIFOWithinSamePriority(t *testing.T) {
	s := NewPriorityScheduler(1, 16, 5*time.Second)

	holdRelease, err := s.Acquire(context.Background(), 2)
	if err != nil {
		t.Fatalf("initial Acquire failed: %v", err)
	}

	const n = 10
	// Use a gate channel so each waiter hands control cleanly after recording its ID.
	acquired := make(chan int, n)
	proceed := make(chan struct{})
	var wg sync.WaitGroup

	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			rel, err := s.Acquire(context.Background(), 2)
			if err != nil {
				t.Errorf("waiter %d Acquire failed: %v", idx, err)
				return
			}
			acquired <- idx
			<-proceed
			rel()
		}(i)
		waitForQueuedCount(t, s, i+1)
	}

	holdRelease()
	for i := 0; i < n; i++ {
		got := <-acquired
		if got != i {
			t.Fatalf("FIFO order mismatch at step %d: got waiter %d, want %d", i, got, i)
		}
		proceed <- struct{}{}
	}
	wg.Wait()

	st := s.Stats()
	if st.Active != 0 || st.Queued != 0 {
		t.Fatalf("expected empty scheduler after drain, got %+v", st)
	}
}

func TestPriorityScheduler_QueueDepthShedding(t *testing.T) {
	t.Run("shed_when_queue_full", func(t *testing.T) {
		s := NewPriorityScheduler(1, 2, 5*time.Second)

		holdRel, err := s.Acquire(context.Background(), 0)
		if err != nil {
			t.Fatalf("initial Acquire failed: %v", err)
		}

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		var wg sync.WaitGroup
		for i := 0; i < 2; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				rel, err := s.Acquire(ctx, 1)
				if err == nil {
					rel()
				}
			}()
			waitForQueuedCount(t, s, i+1)
		}

		_, err = s.Acquire(context.Background(), 0)
		var gwErr *domain.GatewayError
		if !errors.As(err, &gwErr) {
			t.Fatalf("expected *domain.GatewayError, got %T (%v)", err, err)
		}
		if gwErr.StatusCode != http.StatusTooManyRequests {
			t.Fatalf("StatusCode = %d, want %d", gwErr.StatusCode, http.StatusTooManyRequests)
		}
		if gwErr.Type != domain.ErrorTypeRateLimit {
			t.Fatalf("Type = %q, want %q", gwErr.Type, domain.ErrorTypeRateLimit)
		}
		if gwErr.Code != "scheduler_queue_full" {
			t.Fatalf("Code = %q, want %q", gwErr.Code, "scheduler_queue_full")
		}
		if !gwErr.Retryable {
			t.Fatalf("expected Retryable = true")
		}

		st := s.Stats()
		if st.Active != 1 || st.Queued != 2 || st.Rejected != 1 {
			t.Fatalf("unexpected stats after shedding: %+v", st)
		}

		holdRel()
		wg.Wait()
	})

	t.Run("zero_queue_depth_sheds_immediately", func(t *testing.T) {
		s := NewPriorityScheduler(1, 0, time.Second)
		holdRel, err := s.Acquire(context.Background(), 0)
		if err != nil {
			t.Fatalf("initial Acquire failed: %v", err)
		}
		defer holdRel()

		_, err = s.Acquire(context.Background(), 0)
		var gwErr *domain.GatewayError
		if !errors.As(err, &gwErr) || gwErr.StatusCode != http.StatusTooManyRequests || gwErr.Code != "scheduler_queue_full" {
			t.Fatalf("expected 429 scheduler_queue_full, got %v", err)
		}
	})
}

func TestPriorityScheduler_WaitTimeout(t *testing.T) {
	s := NewPriorityScheduler(1, 4, 25*time.Millisecond)

	holdRel, err := s.Acquire(context.Background(), 0)
	if err != nil {
		t.Fatalf("initial Acquire failed: %v", err)
	}

	_, err = s.Acquire(context.Background(), 1)
	var gwErr *domain.GatewayError
	if !errors.As(err, &gwErr) {
		t.Fatalf("expected *domain.GatewayError on wait timeout, got %T (%v)", err, err)
	}
	if gwErr.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("StatusCode = %d, want %d", gwErr.StatusCode, http.StatusServiceUnavailable)
	}
	if gwErr.Code != "scheduler_wait_timeout" {
		t.Fatalf("Code = %q, want %q", gwErr.Code, "scheduler_wait_timeout")
	}
	if !gwErr.Retryable {
		t.Fatalf("expected Retryable = true")
	}

	st := s.Stats()
	if st.Active != 1 || st.Queued != 0 || st.TimedOut != 1 {
		t.Fatalf("unexpected stats after timeout: %+v", st)
	}

	holdRel()
	if st := s.Stats(); st.Active != 0 || st.Queued != 0 {
		t.Fatalf("expected zero active/queued after release, got %+v", st)
	}

	// Verify no slot leak: subsequent acquisition succeeds immediately.
	rel2, err := s.Acquire(context.Background(), 0)
	if err != nil {
		t.Fatalf("post-timeout Acquire failed: %v", err)
	}
	rel2()
}

func TestPriorityScheduler_ContextCancellationCleanup(t *testing.T) {
	s := NewPriorityScheduler(1, 8, 5*time.Second)

	// Already cancelled context should not consume a slot or enqueue.
	cancelledCtx, preCancel := context.WithCancel(context.Background())
	preCancel()
	if _, err := s.Acquire(cancelledCtx, 0); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled for pre-cancelled ctx, got %v", err)
	}
	if st := s.Stats(); st.Active != 0 || st.Queued != 0 {
		t.Fatalf("pre-cancelled ctx mutated stats: %+v", st)
	}

	holdRel, err := s.Acquire(context.Background(), 0)
	if err != nil {
		t.Fatalf("initial Acquire failed: %v", err)
	}

	waiterCtx, cancelWaiter := context.WithCancel(context.Background())
	waiterErrCh := make(chan error, 1)
	go func() {
		_, err := s.Acquire(waiterCtx, 0)
		waiterErrCh <- err
	}()
	waitForQueuedCount(t, s, 1)

	// Add two more waiters at lower priorities so heap.Remove is exercised on a non-leaf/non-empty heap.
	orderCh := make(chan int, 2)
	var wg sync.WaitGroup
	for _, p := range []int{3, 1} {
		wg.Add(1)
		go func(prio int) {
			defer wg.Done()
			rel, err := s.Acquire(context.Background(), prio)
			if err != nil {
				t.Errorf("waiter priority %d failed: %v", prio, err)
				return
			}
			orderCh <- prio
			rel()
		}(p)
	}
	waitForQueuedCount(t, s, 3)

	// Cancel the priority-0 waiter while queued.
	cancelWaiter()
	if err := <-waiterErrCh; !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}

	waitForQueuedCount(t, s, 2)
	if st := s.Stats(); st.TimedOut != 0 || st.Active != 1 {
		t.Fatalf("unexpected stats after ctx cancel: %+v", st)
	}

	holdRel()
	wg.Wait()
	close(orderCh)

	var got []int
	for p := range orderCh {
		got = append(got, p)
	}
	if len(got) != 2 || got[0] != 1 || got[1] != 3 {
		t.Fatalf("expected remaining waiters [1 3], got %v", got)
	}

	if st := s.Stats(); st.Active != 0 || st.Queued != 0 {
		t.Fatalf("expected clean state after drain, got %+v", st)
	}
}

func TestPriorityScheduler_ReleaseIdempotent(t *testing.T) {
	s := NewPriorityScheduler(1, 4, time.Second)

	rel1, err := s.Acquire(context.Background(), 0)
	if err != nil {
		t.Fatalf("Acquire 1 failed: %v", err)
	}

	// Acquire a second request that blocks until rel1 is called.
	acquired2 := make(chan func(), 1)
	go func() {
		rel2, err := s.Acquire(context.Background(), 0)
		if err != nil {
			t.Errorf("Acquire 2 failed: %v", err)
			return
		}
		acquired2 <- rel2
	}()
	waitForQueuedCount(t, s, 1)

	// Call rel1 concurrently multiple times; it must only release once.
	var relWG sync.WaitGroup
	for i := 0; i < 8; i++ {
		relWG.Add(1)
		go func() {
			defer relWG.Done()
			rel1()
		}()
	}
	relWG.Wait()

	rel2 := <-acquired2
	if st := s.Stats(); st.Active != 1 || st.Queued != 0 {
		t.Fatalf("expected Active=1 Queued=0 while second holder active, got %+v", st)
	}

	// Third caller must still see slot occupied until rel2() is called.
	shortCtx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := s.Acquire(shortCtx, 0); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected DeadlineExceeded while rel2 holds slot, got %v", err)
	}

	rel2()
	rel2()
	if st := s.Stats(); st.Active != 0 || st.Queued != 0 {
		t.Fatalf("expected Active=0 Queued=0 after rel2, got %+v", st)
	}
}

func TestPriorityScheduler_ConcurrentStress(t *testing.T) {
	const maxConcurrent = 4
	const maxQueueDepth = 24
	s := NewPriorityScheduler(maxConcurrent, maxQueueDepth, 40*time.Millisecond)

	var currentActive atomic.Int32
	var maxObserved atomic.Int32
	var succeeded atomic.Int64
	var rejected atomic.Int64
	var timedOut atomic.Int64
	var cancelled atomic.Int64

	const workers = 80
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			ctx := context.Background()
			var cancel context.CancelFunc
			if idx%11 == 0 {
				ctx, cancel = context.WithTimeout(ctx, 8*time.Millisecond)
				defer cancel()
			}
			priority := (idx % 6) - 1 // covers -1..4
			rel, err := s.Acquire(ctx, priority)
			if err != nil {
				var gwErr *domain.GatewayError
				if errors.As(err, &gwErr) {
					switch gwErr.Code {
					case "scheduler_queue_full":
						rejected.Add(1)
					case "scheduler_wait_timeout":
						timedOut.Add(1)
					default:
						t.Errorf("unexpected GatewayError code: %s", gwErr.Code)
					}
					return
				}
				if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
					cancelled.Add(1)
					return
				}
				t.Errorf("unexpected error: %v", err)
				return
			}

			cur := currentActive.Add(1)
			for {
				prev := maxObserved.Load()
				if cur <= prev || maxObserved.CompareAndSwap(prev, cur) {
					break
				}
			}
			time.Sleep(time.Duration(1+(idx%4)) * time.Millisecond)
			currentActive.Add(-1)
			rel()
			rel() // exercise idempotency under contention
			succeeded.Add(1)
		}(i)
	}
	wg.Wait()

	if maxObserved.Load() > maxConcurrent {
		t.Fatalf("observed %d concurrent holders, exceeded maxConcurrent=%d", maxObserved.Load(), maxConcurrent)
	}
	if succeeded.Load() == 0 {
		t.Fatalf("expected at least some acquisitions to succeed")
	}
	totalOutcomes := succeeded.Load() + rejected.Load() + timedOut.Load() + cancelled.Load()
	if totalOutcomes != workers {
		t.Fatalf("outcome sum = %d, want %d", totalOutcomes, workers)
	}

	st := s.Stats()
	if st.Active != 0 || st.Queued != 0 {
		t.Fatalf("expected drained scheduler after stress test, got %+v", st)
	}
	if int64(st.Rejected) != rejected.Load() {
		t.Fatalf("stats.Rejected = %d, observed = %d", st.Rejected, rejected.Load())
	}
	// Note: st.TimedOut may be >= timedOut.Load() if a waiter timed out concurrently with cancellation/handoff,
	// here waitTimeout is independent of ctx so counts should match closely.
	if st.TimedOut < uint64(timedOut.Load()) {
		t.Fatalf("stats.TimedOut = %d < observed %d", st.TimedOut, timedOut.Load())
	}

	// Verify scheduler remains healthy after stress.
	rel, err := s.Acquire(context.Background(), 0)
	if err != nil {
		t.Fatalf("post-stress Acquire failed: %v", err)
	}
	rel()
}
