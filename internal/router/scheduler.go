package router

import (
	"container/heap"
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
)

// SchedulerConfig configures bounded concurrency and priority queuing for PriorityScheduler.
type SchedulerConfig struct {
	// Enabled toggles concurrency bounding. When false or MaxConcurrent <= 0,
	// Acquire operates in pass-through mode without queuing or shedding.
	Enabled bool
	// MaxConcurrent is the maximum number of active concurrent slots.
	// Values <= 0 disable concurrency bounding.
	MaxConcurrent int
	// MaxQueueDepth is the maximum number of requests permitted to wait in the queue.
	// Values <= 0 disable queuing so excess requests are immediately rejected.
	MaxQueueDepth int
	// QueueWaitTimeout bounds how long a queued request waits for a slot.
	// Values <= 0 impose no scheduler-level timeout beyond the caller context.
	QueueWaitTimeout time.Duration
}

// SchedulerStats reports point-in-time utilization and shedding counters for a PriorityScheduler.
type SchedulerStats struct {
	Active   int    `json:"active"`
	Queued   int    `json:"queued"`
	Rejected uint64 `json:"rejected"`
	TimedOut uint64 `json:"timed_out"`
}

type schedulerWaiter struct {
	priority int
	seq      uint64
	index    int
	granted  bool
	ready    chan struct{}
}

type waiterHeap []*schedulerWaiter

func (h waiterHeap) Len() int { return len(h) }

func (h waiterHeap) Less(i, j int) bool {
	if h[i].priority != h[j].priority {
		return h[i].priority < h[j].priority
	}
	return h[i].seq < h[j].seq
}

func (h waiterHeap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
	h[i].index = i
	h[j].index = j
}

func (h *waiterHeap) Push(x any) {
	w := x.(*schedulerWaiter)
	w.index = len(*h)
	*h = append(*h, w)
}

func (h *waiterHeap) Pop() any {
	old := *h
	n := len(old)
	w := old[n-1]
	old[n-1] = nil // avoid retaining pointer references in backing array
	w.index = -1
	*h = old[:n-1]
	return w
}

// PriorityScheduler enforces bounded concurrency with a priority-ordered waiting queue.
// Lower priority numbers are served first (0 is highest; negative values are normalized to 0),
// with FIFO ordering among waiters of equal priority.
type PriorityScheduler struct {
	enabled       bool
	maxConcurrent int
	maxQueueDepth int
	waitTimeout   time.Duration

	mu       sync.Mutex
	active   int
	seq      uint64
	waiters  waiterHeap
	rejected uint64
	timedOut uint64
}

// NewPriorityScheduler creates a PriorityScheduler from explicit capacity and timeout parameters.
// When maxConcurrent <= 0, the scheduler runs in unlimited pass-through mode.
func NewPriorityScheduler(maxConcurrent, maxQueueDepth int, waitTimeout time.Duration) *PriorityScheduler {
	return NewPrioritySchedulerWithConfig(SchedulerConfig{
		Enabled:          maxConcurrent > 0,
		MaxConcurrent:    maxConcurrent,
		MaxQueueDepth:    maxQueueDepth,
		QueueWaitTimeout: waitTimeout,
	})
}

// NewPrioritySchedulerWithConfig creates a PriorityScheduler from cfg.
func NewPrioritySchedulerWithConfig(cfg SchedulerConfig) *PriorityScheduler {
	enabled := cfg.Enabled && cfg.MaxConcurrent > 0
	maxQueue := cfg.MaxQueueDepth
	if maxQueue < 0 {
		maxQueue = 0
	}
	return &PriorityScheduler{
		enabled:       enabled,
		maxConcurrent: cfg.MaxConcurrent,
		maxQueueDepth: maxQueue,
		waitTimeout:   cfg.QueueWaitTimeout,
	}
}

// Acquire obtains an execution slot or waits in the priority queue until one becomes available,
// ctx is cancelled, or QueueWaitTimeout elapses. Callers must invoke the returned release function
// when done; release is idempotent.
func (s *PriorityScheduler) Acquire(ctx context.Context, priority int) (func(), error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if s == nil || !s.enabled {
		return func() {}, nil
	}

	if priority < 0 {
		priority = 0
	}

	s.mu.Lock()
	if s.active < s.maxConcurrent && len(s.waiters) == 0 {
		s.active++
		s.mu.Unlock()
		return s.newReleaseFunc(), nil
	}

	if len(s.waiters) >= s.maxQueueDepth {
		s.rejected++
		s.mu.Unlock()
		return nil, &domain.GatewayError{
			StatusCode: http.StatusTooManyRequests,
			Type:       domain.ErrorTypeRateLimit,
			Code:       "scheduler_queue_full",
			Message:    "scheduler queue capacity exceeded",
			Retryable:  true,
		}
	}

	s.seq++
	w := &schedulerWaiter{
		priority: priority,
		seq:      s.seq,
		index:    -1,
		ready:    make(chan struct{}),
	}
	heap.Push(&s.waiters, w)
	s.mu.Unlock()

	var timer *time.Timer
	var timeoutCh <-chan time.Time
	if s.waitTimeout > 0 {
		timer = time.NewTimer(s.waitTimeout)
		defer timer.Stop()
		timeoutCh = timer.C
	}

	select {
	case <-w.ready:
		return s.newReleaseFunc(), nil
	case <-timeoutCh:
		s.cancelWaiter(w, true)
		return nil, &domain.GatewayError{
			StatusCode: http.StatusServiceUnavailable,
			Type:       domain.ErrorTypeRateLimit,
			Code:       "scheduler_wait_timeout",
			Message:    "scheduler queue wait timeout exceeded",
			Retryable:  true,
		}
	case <-ctx.Done():
		s.cancelWaiter(w, false)
		return nil, ctx.Err()
	}
}

// Stats returns a snapshot of current active slots, queued waiters, and shedding counters.
func (s *PriorityScheduler) Stats() SchedulerStats {
	if s == nil {
		return SchedulerStats{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return SchedulerStats{
		Active:   s.active,
		Queued:   len(s.waiters),
		Rejected: s.rejected,
		TimedOut: s.timedOut,
	}
}

func (s *PriorityScheduler) newReleaseFunc() func() {
	var once sync.Once
	return func() {
		once.Do(func() {
			s.mu.Lock()
			s.releaseLocked()
			s.mu.Unlock()
		})
	}
}

func (s *PriorityScheduler) cancelWaiter(w *schedulerWaiter, isTimeout bool) {
	s.mu.Lock()
	if isTimeout {
		s.timedOut++
	}
	if w.granted {
		// Ownership of an active slot was already transferred to this waiter before
		// it abandoned waiting; hand it off or decrement active so no slot leaks.
		s.releaseLocked()
	} else if w.index >= 0 {
		heap.Remove(&s.waiters, w.index)
	}
	s.mu.Unlock()
}

func (s *PriorityScheduler) releaseLocked() {
	if len(s.waiters) > 0 {
		w := heap.Pop(&s.waiters).(*schedulerWaiter)
		// Slot transfers directly from the releasing holder to w; s.active stays unchanged.
		w.granted = true
		close(w.ready)
		return
	}
	if s.active > 0 {
		s.active--
	}
}
