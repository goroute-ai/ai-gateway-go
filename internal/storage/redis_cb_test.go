package storage

import (
	"errors"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/sony/gobreaker/v2"
)

func TestRedisFabric_CBStateAndCode(t *testing.T) {
	var nilFabric *RedisFabric
	if nilFabric.CBStateCode() != 0 || nilFabric.CBState() != "closed" {
		t.Fatalf("expected nil fabric to report closed/0, got %s/%d", nilFabric.CBState(), nilFabric.CBStateCode())
	}

	disabled := NewRedisFabric("", "", 0)
	if disabled.CBStateCode() != 0 || disabled.CBState() != "closed" {
		t.Fatalf("expected disabled fabric to report closed/0, got %s/%d", disabled.CBState(), disabled.CBStateCode())
	}

	mr := miniredis.RunT(t)
	f := &RedisFabric{
		client: redis.NewClient(&redis.Options{Addr: mr.Addr()}),
		cb: gobreaker.NewCircuitBreaker[any](gobreaker.Settings{
			Name:        "test-redis-cb",
			MaxRequests: 1,
			Timeout:     30 * time.Millisecond,
			ReadyToTrip: func(counts gobreaker.Counts) bool {
				return counts.ConsecutiveFailures >= 2
			},
			IsSuccessful: func(err error) bool {
				return err == nil || errors.Is(err, redis.Nil)
			},
		}),
	}
	t.Cleanup(func() { _ = f.client.Close() })

	if f.CBStateCode() != 0 || f.CBState() != "closed" {
		t.Fatalf("expected initial closed/0, got %s/%d", f.CBState(), f.CBStateCode())
	}

	// Close miniredis and fail 2 calls to open the breaker.
	mr.Close()
	for i := 0; i < 2; i++ {
		_, _ = f.Execute(func(rdb redis.UniversalClient) (any, error) {
			return nil, errors.New("connection refused")
		})
	}
	if f.CBStateCode() != 2 || f.CBState() != "open" {
		t.Fatalf("expected open/2 after consecutive failures, got %s/%d", f.CBState(), f.CBStateCode())
	}

	// Wait past Timeout to enter half_open, then verify recovery to closed.
	time.Sleep(45 * time.Millisecond)
	if f.CBStateCode() != 1 || f.CBState() != "half_open" {
		t.Fatalf("expected half_open/1 after timeout, got %s/%d", f.CBState(), f.CBStateCode())
	}

	_, err := f.Execute(func(rdb redis.UniversalClient) (any, error) {
		return "OK", nil
	})
	if err != nil {
		t.Fatalf("expected half_open probe to succeed, got %v", err)
	}
	if f.CBStateCode() != 0 || f.CBState() != "closed" {
		t.Fatalf("expected closed/0 after successful probe, got %s/%d", f.CBState(), f.CBStateCode())
	}
}
