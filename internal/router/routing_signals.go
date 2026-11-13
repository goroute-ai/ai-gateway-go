package router

import (
	"context"
	"crypto/sha256"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/redis/go-redis/v9"
)

const routingSignalTTLSeconds = 600

var startRoutingSignalScript = redis.NewScript(`
local now = tonumber(ARGV[1])
local window_start = tonumber(redis.call('HGET', KEYS[1], 'window_start') or '0')
if window_start == 0 or now - window_start >= 60 then
  redis.call('HSET', KEYS[1], 'used_rpm', 0, 'used_tpm', 0, 'window_start', now)
end
redis.call('HINCRBY', KEYS[1], 'in_flight', 1)
redis.call('HINCRBY', KEYS[1], 'used_rpm', 1)
redis.call('EXPIRE', KEYS[1], ARGV[2])
return 1
`)

var endRoutingSignalScript = redis.NewScript(`
local now = tonumber(ARGV[1])
local window_start = tonumber(redis.call('HGET', KEYS[1], 'window_start') or '0')
if window_start == 0 or now - window_start >= 60 then
  redis.call('HSET', KEYS[1], 'used_rpm', 0, 'used_tpm', 0, 'window_start', now)
end
local in_flight = redis.call('HINCRBY', KEYS[1], 'in_flight', -1)
if in_flight < 0 then redis.call('HSET', KEYS[1], 'in_flight', 0) end
redis.call('HINCRBY', KEYS[1], 'used_tpm', ARGV[2])
local latency = tonumber(ARGV[3])
if latency and latency > 0 then
  local ewma_lat = tonumber(redis.call('HGET', KEYS[1], 'ewma_latency_ms') or '0')
  if ewma_lat == 0 then ewma_lat = latency else ewma_lat = 0.3 * latency + 0.7 * ewma_lat end
  redis.call('HSET', KEYS[1], 'ewma_latency_ms', ewma_lat)
end
local ttft = tonumber(ARGV[4])
if ttft and ttft > 0 then
  local ewma_ttft = tonumber(redis.call('HGET', KEYS[1], 'ewma_ttft_ms') or '0')
  if ewma_ttft == 0 then ewma_ttft = ttft else ewma_ttft = 0.3 * ttft + 0.7 * ewma_ttft end
  redis.call('HSET', KEYS[1], 'ewma_ttft_ms', ewma_ttft)
end
redis.call('EXPIRE', KEYS[1], ARGV[5])
return 1
`)

func routingSignalKey(deploymentID string) string {
	return fmt.Sprintf("gw:routing:signals:%x", sha256.Sum256([]byte(deploymentID)))
}

func (lb *LoadBalancer) readSharedSignals(candidates []*domain.Deployment) (map[string]deploymentTelemetry, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	res, err := lb.redis.Execute(func(rdb redis.UniversalClient) (any, error) {
		pipe := rdb.Pipeline()
		commands := make(map[string]*redis.MapStringStringCmd, len(candidates))
		for _, deployment := range candidates {
			commands[deployment.ID] = pipe.HGetAll(ctx, routingSignalKey(deployment.ID))
		}
		_, err := pipe.Exec(ctx)
		if err != nil && err != redis.Nil {
			return nil, err
		}
		out := make(map[string]deploymentTelemetry, len(commands))
		for deploymentID, command := range commands {
			fields, err := command.Result()
			if err != nil {
				return nil, err
			}
			metric, err := parseRoutingSignal(fields)
			if err != nil {
				return nil, fmt.Errorf("deployment %q: %w", deploymentID, err)
			}
			out[deploymentID] = metric
		}
		return out, nil
	})
	if err != nil {
		return nil, err
	}
	signals, ok := res.(map[string]deploymentTelemetry)
	if !ok {
		return nil, fmt.Errorf("unexpected routing signal result %T", res)
	}
	return signals, nil
}

func parseRoutingSignal(fields map[string]string) (deploymentTelemetry, error) {
	var metric deploymentTelemetry
	parseInt := func(name string) (int, error) {
		value := fields[name]
		if value == "" {
			return 0, nil
		}
		parsed, err := strconv.Atoi(value)
		if err != nil {
			return 0, fmt.Errorf("parse %s: %w", name, err)
		}
		return parsed, nil
	}
	var err error
	if metric.inFlight, err = parseInt("in_flight"); err != nil {
		return metric, err
	}
	if metric.usedRPM, err = parseInt("used_rpm"); err != nil {
		return metric, err
	}
	if metric.usedTPM, err = parseInt("used_tpm"); err != nil {
		return metric, err
	}
	if metric.windowStart, err = parseSignalTime(fields["window_start"]); err != nil {
		return metric, err
	}
	if value := fields["ewma_latency_ms"]; value != "" {
		metric.ewmaLatencyMs, err = strconv.ParseFloat(value, 64)
		if err != nil {
			return metric, fmt.Errorf("parse ewma_latency_ms: %w", err)
		}
	}
	if value := fields["ewma_ttft_ms"]; value != "" {
		metric.ewmaTTFTMs, err = strconv.ParseFloat(value, 64)
		if err != nil {
			return metric, fmt.Errorf("parse ewma_ttft_ms: %w", err)
		}
	}
	return metric, nil
}

func parseSignalTime(value string) (time.Time, error) {
	if value == "" {
		return time.Time{}, nil
	}
	seconds, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return time.Time{}, fmt.Errorf("parse window_start: %w", err)
	}
	return time.Unix(seconds, 0), nil
}

func (lb *LoadBalancer) setSharedDegraded(degraded bool, strategy string) {
	lb.sharedChecked.Store(true)
	if degraded {
		if lb.sharedDegraded.CompareAndSwap(false, true) {
			slog.Warn("adaptive routing using process-local signals; shared Redis signals unavailable", "event", "routing_signal_store_unavailable", "strategy", strategy)
		}
		return
	}
	lb.sharedDegraded.Store(false)
}

// SharedSignalsAvailable reports whether the last Redis-backed adaptive routing operation succeeded.
// It is false when shared routing is not configured or has reported a Redis error.
func (lb *LoadBalancer) SharedSignalsAvailable() bool {
	return lb.redis != nil && lb.redis.Client() != nil && lb.sharedChecked.Load() && !lb.sharedDegraded.Load()
}
