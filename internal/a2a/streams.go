package a2a

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
	"github.com/redis/go-redis/v9"
)

// StreamSubscriber implements the robust "Subscribe-First" SSE protocol for A2A tasks.
type StreamSubscriber struct {
	repo  storage.Repository
	redis *storage.RedisFabric
}

// NewStreamSubscriber constructs a StreamSubscriber.
func NewStreamSubscriber(repo storage.Repository, redis *storage.RedisFabric) *StreamSubscriber {
	return &StreamSubscriber{
		repo:  repo,
		redis: redis,
	}
}

// SubscribeTaskStream handles `GET /a2a/v1/agents/{agentSlug}/tasks/{taskID}:subscribe`.
func (s *StreamSubscriber) SubscribeTaskStream(
	w http.ResponseWriter,
	r *http.Request,
	idCtx *domain.IdentityContext,
	agentSlug string,
	taskID string,
	visibilityMode string,
) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}

	ctx := r.Context()

	// Verify task existence and visibility
	task, err := s.repo.GetA2ATask(ctx, taskID)
	if err != nil || task == nil {
		http.Error(w, fmt.Sprintf("Task %q not found", taskID), http.StatusNotFound)
		return
	}

	if !CheckTaskVisibility(task, idCtx, visibilityMode) {
		http.Error(w, fmt.Sprintf("Task %q not found", taskID), http.StatusNotFound)
		return
	}

	// Determine starting sequence: check Last-Event-ID or query param after_seq
	var afterSeq int64 = 0
	if lastEvID := r.Header.Get("Last-Event-ID"); lastEvID != "" {
		if seq, err := strconv.ParseInt(strings.TrimSpace(lastEvID), 10, 64); err == nil {
			afterSeq = seq
		}
	} else if qSeq := r.URL.Query().Get("after_seq"); qSeq != "" {
		if seq, err := strconv.ParseInt(strings.TrimSpace(qSeq), 10, 64); err == nil {
			afterSeq = seq
		}
	}

	// 1. Subscribe to Redis FIRST (buffer incoming events while backfilling)
	channelName := fmt.Sprintf("gw:a2a:events:%s", taskID)
	liveEventCh := make(chan []byte, 256)
	var pubsub *redis.PubSub

	if s.redis != nil {
		_, _ = s.redis.Execute(func(rdb redis.UniversalClient) (any, error) {
			pubsub = rdb.Subscribe(ctx, channelName)
			return nil, nil
		})
		if pubsub != nil {
			defer pubsub.Close()
			go func() {
				ch := pubsub.Channel()
				for msg := range ch {
					select {
					case liveEventCh <- []byte(msg.Payload):
					default:
					}
				}
			}()
		}
	}

	// Set SSE Headers
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)

	// Send initial connection comment
	_, _ = fmt.Fprint(w, ": connected\n\n")
	flusher.Flush()

	// 2. Backfill historical events from persistent database snapshot
	var lastSentSeq int64 = afterSeq
	historicalEvents, _ := s.repo.ListA2ATaskEvents(ctx, taskID, afterSeq, 1000)
	for _, ev := range historicalEvents {
		s.writeSSEEvent(w, ev.EventSeq, ev.EventType, ev.PayloadJSON)
		flusher.Flush()
		if ev.EventSeq > lastSentSeq {
			lastSentSeq = ev.EventSeq
		}
	}

	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	// 3. Process buffered live events & live tail
	for {
		select {
		case <-ctx.Done():
			return

		case payloadBytes, ok := <-liveEventCh:
			if !ok {
				return
			}
			var liveEv struct {
				EventSeq  int64  `json:"event_seq"`
				EventType string `json:"event_type"`
			}
			_ = json.Unmarshal(payloadBytes, &liveEv)

			// Deduplicate: ignore events already sent in the historical backfill
			if liveEv.EventSeq > 0 && liveEv.EventSeq <= lastSentSeq {
				continue
			}

			// Gap detection: if live event skipped a sequence, backfill missing gap from DB
			if liveEv.EventSeq > lastSentSeq+1 {
				gapEvents, _ := s.repo.ListA2ATaskEvents(ctx, taskID, lastSentSeq, int(liveEv.EventSeq-lastSentSeq))
				for _, gev := range gapEvents {
					s.writeSSEEvent(w, gev.EventSeq, gev.EventType, gev.PayloadJSON)
					flusher.Flush()
					if gev.EventSeq > lastSentSeq {
						lastSentSeq = gev.EventSeq
					}
				}
			}

			s.writeSSEEvent(w, liveEv.EventSeq, liveEv.EventType, string(payloadBytes))
			flusher.Flush()
			if liveEv.EventSeq > lastSentSeq {
				lastSentSeq = liveEv.EventSeq
			}

		case <-ticker.C:
			_, _ = fmt.Fprint(w, ": keepalive\n\n")
			flusher.Flush()
		}
	}
}

func (s *StreamSubscriber) writeSSEEvent(w http.ResponseWriter, seq int64, eventType, payload string) {
	if eventType == "" {
		eventType = "message"
	}
	_, _ = fmt.Fprintf(w, "id: %d\nevent: %s\ndata: %s\n\n", seq, eventType, strings.ReplaceAll(payload, "\n", " "))
}
