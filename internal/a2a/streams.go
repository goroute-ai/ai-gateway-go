package a2a

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	a2aspec "github.com/goroute-ai/ai-gateway-go/internal/a2a/spec"
	"github.com/goroute-ai/ai-gateway-go/internal/auth"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
	"github.com/redis/go-redis/v9"
)

// StreamEnvelope is the structured Redis Pub/Sub wire payload produced by StreamPublisher
// and consumed identically by both HTTP SSE StreamSubscriber and gRPC SubscribeToTask.
type StreamEnvelope struct {
	EventSeq       int64           `json:"event_seq"`
	EventType      string          `json:"event_type"`
	State          string          `json:"state"`
	StreamResponse json.RawMessage `json:"stream_response"`
}

// StreamSubscriber implements the "Subscribe-First" A2A v1.0 streaming protocol.
type StreamSubscriber struct {
	repo              storage.Repository
	rbac              *auth.RBACEngine
	redis             *storage.RedisFabric
	bufferCapacity    int
	activeSubscribers atomic.Int64
}

// ActiveSubscribers returns the number of currently active A2A task stream subscriptions.
func (s *StreamSubscriber) ActiveSubscribers() int64 {
	if s == nil {
		return 0
	}
	return s.activeSubscribers.Load()
}

// NewStreamSubscriber constructs a StreamSubscriber with a configurable channel buffer capacity.
func NewStreamSubscriber(repo storage.Repository, rbac *auth.RBACEngine, redis *storage.RedisFabric, bufferCapacity int) *StreamSubscriber {
	if bufferCapacity <= 0 {
		bufferCapacity = 256
	}
	return &StreamSubscriber{
		repo:           repo,
		rbac:           rbac,
		redis:          redis,
		bufferCapacity: bufferCapacity,
	}
}

// SubscribeChannel validates RBAC + cross-agent/tenant visibility, subscribes to Redis FIRST,
// backfills historical task events after `afterSeq`, deduplicates live events, fills sequence
// gaps from durable storage, and closes the returned channel when the task reaches a terminal state
// or ctx is canceled.
func (s *StreamSubscriber) SubscribeChannel(
	ctx context.Context,
	idCtx *domain.IdentityContext,
	agentSlug string,
	taskID string,
	afterSeq int64,
) (<-chan StreamEnvelope, error) {
	if idCtx == nil {
		return nil, ErrTaskNotFound("forbidden", taskID)
	}
	if s.rbac != nil {
		if err := s.rbac.AuthorizeA2AAgent(idCtx, agentSlug); err != nil {
			return nil, ErrTaskNotFound("forbidden", taskID)
		}
	}

	agent, err := s.repo.GetA2AAgentBySlug(ctx, idCtx.OrgID, agentSlug)
	if err != nil || agent == nil {
		return nil, ErrTaskNotFound(fmt.Sprintf("agent %q not found", agentSlug), taskID)
	}

	task, err := s.repo.GetA2ATask(ctx, taskID)
	if err != nil || task == nil {
		return nil, ErrTaskNotFound(fmt.Sprintf("task %q not found", taskID), taskID)
	}

	if !CheckTaskVisibility(task, agent, idCtx) {
		return nil, ErrTaskNotFound(fmt.Sprintf("task %q not found", taskID), taskID)
	}

	// If task is already in a terminal state and caller isn't replaying missed events (`afterSeq < task.LastEventSeq`),
	// reject per A2A v1.0 SubscribeToTask precondition (`UNSUPPORTED_OPERATION` / FailedPrecondition).
	if a2aspec.IsTerminalDomainState(task.State) && afterSeq >= task.LastEventSeq {
		return nil, ErrUnsupportedOperation(fmt.Sprintf("cannot subscribe to task %q already in terminal state %s", taskID, task.State))
	}

	bufCap := s.bufferCapacity
	if bufCap <= 0 {
		bufCap = 256
	}
	outCh := make(chan StreamEnvelope, bufCap)

	// 1. Subscribe to Redis FIRST so no in-flight publication is missed while backfilling DB rows.
	channelName := fmt.Sprintf("gw:a2a:events:%s", taskID)
	liveEventCh := make(chan []byte, bufCap)
	var pubsub *redis.PubSub

	if s.redis != nil {
		_, _ = s.redis.Execute(func(rdb redis.UniversalClient) (any, error) {
			pubsub = rdb.Subscribe(ctx, channelName)
			return nil, nil
		})
	}

	s.activeSubscribers.Add(1)
	go func() {
		defer s.activeSubscribers.Add(-1)
		defer close(outCh)
		if pubsub != nil {
			defer pubsub.Close()
			go func() {
				ch := pubsub.Channel()
				for msg := range ch {
					if msg == nil {
						continue
					}
					select {
					case liveEventCh <- []byte(msg.Payload):
					case <-ctx.Done():
						return
					}
				}
			}()
		}

		// 2. Backfill historical events from persistent storage snapshot.
		lastSentSeq := afterSeq
		historicalEvents, _ := s.repo.ListA2ATaskEvents(ctx, taskID, afterSeq, 1000)
		for _, ev := range historicalEvents {
			env := StreamEnvelope{
				EventSeq:       ev.EventSeq,
				EventType:      ev.EventType,
				State:          task.State,
				StreamResponse: json.RawMessage(ev.PayloadJSON),
			}
			select {
			case outCh <- env:
			case <-ctx.Done():
				return
			}
			if ev.EventSeq > lastSentSeq {
				lastSentSeq = ev.EventSeq
			}
		}

		if a2aspec.IsTerminalDomainState(task.State) {
			return
		}

		pollTicker := time.NewTicker(250 * time.Millisecond)
		defer pollTicker.Stop()

		// 3. Process live Redis events with deduplication + DB gap backfill, and close on terminal state.
		for {
			select {
			case <-ctx.Done():
				return

			case payloadBytes, ok := <-liveEventCh:
				if !ok {
					return
				}
				env := decodeStreamEnvelope(payloadBytes)

				if env.EventSeq > 0 && env.EventSeq <= lastSentSeq {
					continue
				}

				if env.EventSeq > lastSentSeq+1 {
					gapEvents, _ := s.repo.ListA2ATaskEvents(ctx, taskID, lastSentSeq, int(env.EventSeq-lastSentSeq-1))
					for _, gev := range gapEvents {
						gEnv := StreamEnvelope{
							EventSeq:       gev.EventSeq,
							EventType:      gev.EventType,
							StreamResponse: json.RawMessage(gev.PayloadJSON),
						}
						select {
						case outCh <- gEnv:
						case <-ctx.Done():
							return
						}
						if gev.EventSeq > lastSentSeq {
							lastSentSeq = gev.EventSeq
						}
					}
				}

				select {
				case outCh <- env:
				case <-ctx.Done():
					return
				}
				if env.EventSeq > lastSentSeq {
					lastSentSeq = env.EventSeq
				}

				if a2aspec.IsTerminalDomainState(env.State) {
					return
				}
				if latest, err := s.repo.GetA2ATask(ctx, taskID); err == nil && latest != nil && a2aspec.IsTerminalDomainState(latest.State) {
					return
				}

			case <-pollTicker.C:
				// Storage fallback when Redis is absent or a state transition happened in-memory/other pod.
				missingEvents, _ := s.repo.ListA2ATaskEvents(ctx, taskID, lastSentSeq, 100)
				for _, mev := range missingEvents {
					mEnv := StreamEnvelope{
						EventSeq:       mev.EventSeq,
						EventType:      mev.EventType,
						StreamResponse: json.RawMessage(mev.PayloadJSON),
					}
					select {
					case outCh <- mEnv:
					case <-ctx.Done():
						return
					}
					if mev.EventSeq > lastSentSeq {
						lastSentSeq = mev.EventSeq
					}
				}
				if latest, err := s.repo.GetA2ATask(ctx, taskID); err == nil && latest != nil && a2aspec.IsTerminalDomainState(latest.State) {
					return
				}
			}
		}
	}()

	return outCh, nil
}

// SubscribeTaskStream handles HTTP SSE streaming (`GET` or compat `POST` `.../tasks/{taskID}:subscribe`).
func (s *StreamSubscriber) SubscribeTaskStream(
	w http.ResponseWriter,
	r *http.Request,
	idCtx *domain.IdentityContext,
	agentSlug string,
	taskID string,
) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		WriteHTTPError(w, ErrInternal("streaming unsupported by response writer"))
		return
	}

	var afterSeq int64
	if lastEvID := strings.TrimSpace(r.Header.Get(HeaderLastEventID)); lastEvID != "" {
		if seq, err := strconv.ParseInt(lastEvID, 10, 64); err == nil {
			afterSeq = seq
		}
	} else if qSeq := strings.TrimSpace(r.URL.Query().Get("after_seq")); qSeq != "" {
		if seq, err := strconv.ParseInt(qSeq, 10, 64); err == nil {
			afterSeq = seq
		}
	}

	ch, err := s.SubscribeChannel(r.Context(), idCtx, agentSlug, taskID, afterSeq)
	if err != nil {
		WriteHTTPError(w, err)
		return
	}

	w.Header().Set("Content-Type", MediaTypeSSE)
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.Header().Set(HeaderA2AVersion, a2aspec.SupportedA2AVersion)
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	keepalive := time.NewTicker(15 * time.Second)
	defer keepalive.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case env, ok := <-ch:
			if !ok {
				return
			}
			writeSSEStreamFrame(w, env.EventSeq, string(env.StreamResponse))
			flusher.Flush()
		case <-keepalive.C:
			_, _ = fmt.Fprint(w, ": keepalive\n\n")
			flusher.Flush()
		}
	}
}

func decodeStreamEnvelope(payloadBytes []byte) StreamEnvelope {
	var env StreamEnvelope
	if err := json.Unmarshal(payloadBytes, &env); err == nil && len(env.StreamResponse) > 0 {
		return env
	}
	return StreamEnvelope{
		StreamResponse: json.RawMessage(payloadBytes),
	}
}

func writeSSEStreamFrame(w http.ResponseWriter, seq int64, streamRespJSON string) {
	trimmed := strings.ReplaceAll(strings.TrimSpace(streamRespJSON), "\n", " ")
	if seq > 0 {
		_, _ = fmt.Fprintf(w, "id: %d\ndata: %s\n\n", seq, trimmed)
		return
	}
	_, _ = fmt.Fprintf(w, "data: %s\n\n", trimmed)
}
