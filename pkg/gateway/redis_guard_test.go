package gateway

import (
	"testing"

	"github.com/goroute-ai/ai-gateway-go/internal/config"
)

func TestShouldInitSDKRedis(t *testing.T) {
	tests := []struct {
		name              string
		redisAddrEnv      string
		redisAddrsEnv     string
		pgDSNEnv          string
		storageCfg        config.StorageConfig
		explicitRawConfig bool
		want              bool
	}{
		{
			name:     "postgres only with default localhost redis does not init redis",
			pgDSNEnv: "postgres://user:pass@pg.internal:5432/gw",
			storageCfg: config.StorageConfig{
				Mode:      "postgres",
				RedisAddr: "localhost:6379",
			},
			want: false,
		},
		{
			name:     "postgres only with blank redis addr does not init redis",
			pgDSNEnv: "postgres://user:pass@pg.internal:5432/gw",
			storageCfg: config.StorageConfig{
				Mode:      "postgres",
				RedisAddr: "",
			},
			want: false,
		},
		{
			name:         "env GATEWAY_REDIS_ADDR enables redis init",
			pgDSNEnv:     "postgres://user:pass@pg.internal:5432/gw",
			redisAddrEnv: "127.0.0.1:6379",
			storageCfg: config.StorageConfig{
				Mode:      "postgres",
				RedisAddr: "127.0.0.1:6379",
			},
			want: true,
		},
		{
			name:              "explicit config file redis enables redis init even on localhost",
			storageCfg:        config.StorageConfig{RedisAddr: "localhost:6379"},
			explicitRawConfig: true,
			want:              true,
		},
		{
			name:       "non-default configured redis addrs enables redis init",
			storageCfg: config.StorageConfig{RedisAddrs: []string{"redis-1:6379"}},
			want:       true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("GATEWAY_POSTGRES_DSN", tc.pgDSNEnv)
			t.Setenv("GATEWAY_REDIS_ADDR", tc.redisAddrEnv)
			t.Setenv("GATEWAY_REDIS_ADDRS", tc.redisAddrsEnv)

			cfg := &config.Config{Storage: tc.storageCfg}
			if got := shouldInitSDKRedis(cfg, tc.explicitRawConfig); got != tc.want {
				t.Fatalf("shouldInitSDKRedis(%+v, explicit=%v) = %v, want %v", tc.storageCfg, tc.explicitRawConfig, got, tc.want)
			}
		})
	}
}
