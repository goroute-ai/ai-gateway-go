package storage

import (
	"context"
	"errors"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func TestNewRedisFabricAndOptions(t *testing.T) {
	t.Run("empty addr disables client", func(t *testing.T) {
		f := NewRedisFabric("", "", 0)
		if f.Client() != nil {
			t.Fatalf("expected nil client for empty addr, got %T", f.Client())
		}
		if err := f.Ping(context.Background()); !errors.Is(err, redis.Nil) {
			t.Fatalf("expected redis.Nil from Ping, got %v", err)
		}
		if _, err := f.Execute(func(rdb redis.UniversalClient) (any, error) {
			return rdb.Ping(context.Background()).Result()
		}); !errors.Is(err, redis.Nil) {
			t.Fatalf("expected redis.Nil from Execute, got %v", err)
		}
	})

	t.Run("nil or empty options disables client", func(t *testing.T) {
		if f := NewRedisFabricWithOptions(nil); f.Client() != nil {
			t.Fatalf("expected nil client for nil options, got %T", f.Client())
		}
		if f := NewRedisFabricWithOptions(&redis.UniversalOptions{}); f.Client() != nil {
			t.Fatalf("expected nil client for empty addrs, got %T", f.Client())
		}
	})

	t.Run("single addr constructs standalone client", func(t *testing.T) {
		mr := miniredis.RunT(t)
		f := NewRedisFabric(mr.Addr(), "", 0)
		t.Cleanup(func() { _ = f.Client().Close() })

		if _, ok := f.Client().(*redis.Client); !ok {
			t.Fatalf("expected *redis.Client for single addr, got %T", f.Client())
		}
		if err := f.Ping(context.Background()); err != nil {
			t.Fatalf("Ping failed: %v", err)
		}
	})

	t.Run("multiple addrs constructs cluster client", func(t *testing.T) {
		f := NewRedisFabricWithOptions(&redis.UniversalOptions{
			Addrs: []string{"127.0.0.1:7000", "127.0.0.1:7001"},
		})
		t.Cleanup(func() { _ = f.Client().Close() })

		if _, ok := f.Client().(*redis.ClusterClient); !ok {
			t.Fatalf("expected *redis.ClusterClient for multiple addrs, got %T", f.Client())
		}
	})

	t.Run("master name constructs sentinel failover client", func(t *testing.T) {
		f := NewRedisFabricWithOptions(&redis.UniversalOptions{
			Addrs:      []string{"127.0.0.1:26379"},
			MasterName: "mymaster",
		})
		t.Cleanup(func() { _ = f.Client().Close() })

		if _, ok := f.Client().(*redis.Client); !ok {
			t.Fatalf("expected *redis.Client for sentinel failover client, got %T", f.Client())
		}
	})
}
