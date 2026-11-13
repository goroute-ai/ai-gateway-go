package mcp

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
	"github.com/redis/go-redis/v9"
)

// SubscriptionManager coordinates real-time MCP SSE notifications and Redis Pub/Sub multiplexing.
type SubscriptionManager struct {
	redis   *storage.RedisFabric
	clients map[string]chan []byte
	mu      sync.RWMutex
}

// NewSubscriptionManager creates a new MCP subscription manager.
func NewSubscriptionManager(redisFabric *storage.RedisFabric) *SubscriptionManager {
	return &SubscriptionManager{
		redis:   redisFabric,
		clients: make(map[string]chan []byte),
	}
}

// Subscribe registers a new SSE client channel.
func (sm *SubscriptionManager) Subscribe() (string, chan []byte) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	id := uuid.NewString()
	ch := make(chan []byte, 32)
	sm.clients[id] = ch
	return id, ch
}

// Unsubscribe removes a disconnected SSE client channel.
func (sm *SubscriptionManager) Unsubscribe(id string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if ch, ok := sm.clients[id]; ok {
		delete(sm.clients, id)
		close(ch)
	}
}

// PublishNotification broadcasts a notification to local SSE subscribers and Redis Pub/Sub.
func (sm *SubscriptionManager) PublishNotification(ctx context.Context, orgID string, payload []byte) error {
	if sm.redis != nil {
		_, _ = sm.redis.Execute(func(rdb redis.UniversalClient) (any, error) {
			return rdb.Publish(ctx, "gw:mcp:notif:"+orgID, payload).Result()
		})
	}

	sm.mu.RLock()
	defer sm.mu.RUnlock()
	for _, ch := range sm.clients {
		select {
		case ch <- payload:
		default:
			// Non-blocking drop if channel full
		}
	}
	return nil
}

// ServeSSEStream serves a long-lived SSE connection for MCP notifications (`GET /mcp/subscriptions/listen`).
func (sm *SubscriptionManager) ServeSSEStream(w http.ResponseWriter, r *http.Request, idCtx *domain.IdentityContext) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)

	// Send initial connection confirmation comment
	_, _ = fmt.Fprint(w, ": connected\n\n")
	flusher.Flush()

	clientID, msgCh := sm.Subscribe()
	defer sm.Unsubscribe(clientID)

	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case msg, ok := <-msgCh:
			if !ok {
				return
			}
			_, _ = fmt.Fprintf(w, "data: %s\n\n", string(msg))
			flusher.Flush()
		case <-ticker.C:
			_, _ = fmt.Fprint(w, ": keepalive\n\n")
			flusher.Flush()
		}
	}
}
