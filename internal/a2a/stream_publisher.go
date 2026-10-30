package a2a

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/logger"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
	"github.com/redis/go-redis/v9"
)

// StreamPublisher is a resilient background daemon that drains unpublished A2A task stream
// publications from PostgreSQL and broadcasts them to Redis Pub/Sub channels.
type StreamPublisher struct {
	repo     storage.Repository
	redis    *storage.RedisFabric
	interval time.Duration
	stopCh   chan struct{}
	wg       sync.WaitGroup
}

// NewStreamPublisher constructs a new StreamPublisher worker.
func NewStreamPublisher(repo storage.Repository, redis *storage.RedisFabric, interval time.Duration) *StreamPublisher {
	if interval <= 0 {
		interval = 50 * time.Millisecond
	}
	return &StreamPublisher{
		repo:     repo,
		redis:    redis,
		interval: interval,
		stopCh:   make(chan struct{}),
	}
}

// Start launches the background publishing loop.
func (p *StreamPublisher) Start(ctx context.Context) {
	p.wg.Add(1)
	go p.run(ctx)
}

// Stop cleanly drains and halts the background publishing loop.
func (p *StreamPublisher) Stop() {
	close(p.stopCh)
	p.wg.Wait()
}

func (p *StreamPublisher) run(ctx context.Context) {
	defer p.wg.Done()
	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-p.stopCh:
			return
		case <-ticker.C:
			p.PublishPending(ctx)
		}
	}
}

// PublishPending drains pending publications and broadcasts them to Redis (exported for deterministic tests).
func (p *StreamPublisher) PublishPending(ctx context.Context) error {
	pubs, err := p.repo.ClaimPendingA2AStreamPublications(ctx, 100)
	if err != nil {
		return err
	}
	if len(pubs) == 0 {
		return nil
	}

	for _, pub := range pubs {
		channel := fmt.Sprintf("gw:a2a:events:%s", pub.TaskID)

		if p.redis != nil {
			_, err := p.redis.Execute(func(rdb *redis.Client) (any, error) {
				return rdb.Publish(ctx, channel, pub.PayloadJSON).Result()
			})
			if err != nil {
				logger.WarnContext(ctx, "failed to publish A2A stream event to redis",
					slog.String("publication_id", pub.ID),
					slog.String("task_id", pub.TaskID),
					slog.Int64("event_seq", pub.EventSeq),
					slog.Any("error", err),
				)
				continue
			}
		}

		// Mark success in persistent storage
		_ = p.repo.MarkA2AStreamPublicationSuccess(ctx, pub.ID)
	}
	return nil
}
