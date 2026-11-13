package storage

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestPostgresRepositoryCoalescesConcurrentLookupMisses(t *testing.T) {
	repo := &PostgresRepository{}
	started := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int32
	lookup := func(context.Context) (any, error) {
		calls.Add(1)
		close(started)
		<-release
		return "shared-result", nil
	}

	const followers = 8
	results := make(chan any, followers+1)
	errs := make(chan error, followers+1)
	var wg sync.WaitGroup
	for i := 0; i < followers+1; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			value, err := repo.coalesceLookup(context.Background(), "guardrail:org", lookup)
			results <- value
			errs <- err
		}()
		if i == 0 {
			<-started
		}
	}
	// Keep the leader inside the callback long enough for the remaining callers
	// to join the same in-flight lookup.
	time.Sleep(20 * time.Millisecond)
	close(release)
	wg.Wait()
	close(results)
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("coalesced lookup returned error: %v", err)
		}
	}
	for result := range results {
		if result != "shared-result" {
			t.Fatalf("coalesced result = %#v", result)
		}
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("lookup callback ran %d times, want once", got)
	}
}
