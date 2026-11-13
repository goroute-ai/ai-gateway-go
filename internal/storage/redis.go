package storage

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/sony/gobreaker/v2"
)

const InvalidationChannel = "gw:events:invalidation"

// InvalidationEvent is broadcast over Redis Pub/Sub whenever a VirtualKey, Policy, or Deployment changes.
type InvalidationEvent struct {
	Type       string `json:"type,omitempty"`
	EntityType string `json:"entity_type,omitempty"`
	KeyHash    string `json:"key_hash,omitempty"`
	EntityID   string `json:"entity_id,omitempty"`
	OrgID      string `json:"org_id,omitempty"`
}

// RedisFabric wraps a go-redis UniversalClient with a circuit breaker so Redis degradation never blocks hot-path inference.
type RedisFabric struct {
	client redis.UniversalClient
	cb     *gobreaker.CircuitBreaker[any]
}

// NewRedisFabric creates a RedisFabric for a single Redis endpoint, preserving backward compatibility.
func NewRedisFabric(addr, password string, db int) *RedisFabric {
	if addr == "" {
		return NewRedisFabricWithOptions(nil)
	}
	return NewRedisFabricWithOptions(&redis.UniversalOptions{
		Addrs:    []string{addr},
		Password: password,
		DB:       db,
	})
}

// NewRedisFabricWithOptions creates a RedisFabric backed by redis.NewUniversalClient,
// supporting standalone Redis, Redis Cluster (multiple Addrs), and Redis Sentinel (MasterName).
func NewRedisFabricWithOptions(opts *redis.UniversalOptions) *RedisFabric {
	var rdb redis.UniversalClient
	if opts != nil && len(opts.Addrs) > 0 {
		o := *opts
		if o.DialTimeout == 0 {
			o.DialTimeout = 200 * time.Millisecond
		}
		if o.ReadTimeout == 0 {
			o.ReadTimeout = 50 * time.Millisecond
		}
		if o.WriteTimeout == 0 {
			o.WriteTimeout = 50 * time.Millisecond
		}
		if o.PoolSize == 0 {
			o.PoolSize = 128
		}
		rdb = redis.NewUniversalClient(&o)
	}
	cb := gobreaker.NewCircuitBreaker[any](gobreaker.Settings{
		Name:        "redis-fabric",
		MaxRequests: 3,
		Interval:    30 * time.Second,
		Timeout:     10 * time.Second,
		ReadyToTrip: func(counts gobreaker.Counts) bool {
			return counts.ConsecutiveFailures >= 5
		},
		IsSuccessful: func(err error) bool {
			return err == nil || errors.Is(err, redis.Nil)
		},
	})
	return &RedisFabric{client: rdb, cb: cb}
}

// Client returns the underlying UniversalClient, or nil when Redis is disabled.
func (f *RedisFabric) Client() redis.UniversalClient {
	if f == nil {
		return nil
	}
	return f.client
}

// Ping checks Redis connectivity.
func (f *RedisFabric) Ping(ctx context.Context) error {
	if f == nil || f.client == nil {
		return redis.Nil
	}
	_, err := f.Execute(func(rdb redis.UniversalClient) (any, error) {
		return rdb.Ping(ctx).Result()
	})
	return err
}

// Execute runs a Redis operation protected by the circuit breaker.
func (f *RedisFabric) Execute(fn func(rdb redis.UniversalClient) (any, error)) (any, error) {
	if f == nil || f.client == nil {
		return nil, redis.Nil
	}
	return f.cb.Execute(func() (any, error) {
		return fn(f.client)
	})
}

// PublishInvalidation broadcasts a cache eviction event to all gateway pods.
func (f *RedisFabric) PublishInvalidation(ctx context.Context, ev InvalidationEvent) {
	if f == nil || f.client == nil {
		return
	}
	b, err := json.Marshal(ev)
	if err != nil {
		return
	}
	_, _ = f.Execute(func(rdb redis.UniversalClient) (any, error) {
		return rdb.Publish(ctx, InvalidationChannel, b).Result()
	})
}
