package storage

import (
	"context"
	"encoding/json"
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

// RedisFabric wraps a go-redis Client with a circuit breaker so Redis degradation never blocks hot-path inference.
type RedisFabric struct {
	client *redis.Client
	cb     *gobreaker.CircuitBreaker[any]
}

func NewRedisFabric(addr, password string, db int) *RedisFabric {
	var rdb *redis.Client
	if addr != "" {
		rdb = redis.NewClient(&redis.Options{
			Addr:         addr,
			Password:     password,
			DB:           db,
			DialTimeout:  200 * time.Millisecond,
			ReadTimeout:  50 * time.Millisecond,
			WriteTimeout: 50 * time.Millisecond,
			PoolSize:     128,
		})
	}
	cb := gobreaker.NewCircuitBreaker[any](gobreaker.Settings{
		Name:        "redis-fabric",
		MaxRequests: 3,
		Interval:    30 * time.Second,
		Timeout:     10 * time.Second,
		ReadyToTrip: func(counts gobreaker.Counts) bool {
			return counts.ConsecutiveFailures >= 5
		},
	})
	return &RedisFabric{client: rdb, cb: cb}
}

func (f *RedisFabric) Client() *redis.Client {
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
	_, err := f.Execute(func(rdb *redis.Client) (any, error) {
		return rdb.Ping(ctx).Result()
	})
	return err
}

// Execute runs a Redis operation protected by the circuit breaker.
func (f *RedisFabric) Execute(fn func(rdb *redis.Client) (any, error)) (any, error) {
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
	_, _ = f.Execute(func(rdb *redis.Client) (any, error) {
		return rdb.Publish(ctx, InvalidationChannel, b).Result()
	})
}
