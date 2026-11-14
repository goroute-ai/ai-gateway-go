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
	clients map[string]map[string]chan []byte // orgID -> clientID -> channel
	mu      sync.RWMutex
}

// NewSubscriptionManager creates a new MCP subscription manager.
func NewSubscriptionManager(redisFabric *storage.RedisFabric) *SubscriptionManager {
	return &SubscriptionManager{
		redis:   redisFabric,
		clients: make(map[string]map[string]chan []byte),
	}
}

// Subscribe registers a new SSE client channel scoped to orgID.
func (sm *SubscriptionManager) Subscribe(orgID string) (string, chan []byte) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	id := uuid.NewString()
	ch := make(chan []byte, 32)
	if sm.clients[orgID] == nil {
		sm.clients[orgID] = make(map[string]chan []byte)
	}
	sm.clients[orgID][id] = ch
	return id, ch
}

// Unsubscribe removes a disconnected SSE client channel scoped to orgID.
func (sm *SubscriptionManager) Unsubscribe(orgID, id string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	orgClients, ok := sm.clients[orgID]
	if !ok {
		return
	}
	if ch, exists := orgClients[id]; exists {
		delete(orgClients, id)
		close(ch)
	}
	if len(orgClients) == 0 {
		delete(sm.clients, orgID)
	}
}

// PublishNotification broadcasts a notification to local SSE subscribers in orgID and Redis Pub/Sub.
func (sm *SubscriptionManager) PublishNotification(ctx context.Context, orgID string, payload []byte) error {
	if orgID == "" {
		return fmt.Errorf("mcp subscriptions: orgID is required")
	}

	publishedToRedis := false
	if sm.redis != nil {
		_, err := sm.redis.Execute(func(rdb redis.UniversalClient) (any, error) {
			return rdb.Publish(ctx, "gw:mcp:notif:"+orgID, payload).Result()
		})
		if err == nil {
			publishedToRedis = true
		}
	}

	if !publishedToRedis {
		sm.mu.RLock()
		defer sm.mu.RUnlock()
		for _, ch := range sm.clients[orgID] {
			select {
			case ch <- payload:
			default:
				// Non-blocking drop if channel full
			}
		}
	}
	return nil
}

// ServeSSEStream serves a long-lived SSE connection for MCP notifications (`GET /mcp/subscriptions/listen`).
func (sm *SubscriptionManager) ServeSSEStream(w http.ResponseWriter, r *http.Request, idCtx *domain.IdentityContext) {
	if idCtx == nil || idCtx.OrgID == "" {
		http.Error(w, "Unauthorized: organization context required", http.StatusUnauthorized)
		return
	}
	orgID := idCtx.OrgID

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

	clientID, msgCh := sm.Subscribe(orgID)
	defer sm.Unsubscribe(orgID, clientID)

	var redisCh chan []byte
	if sm.redis != nil {
		var pubsub *redis.PubSub
		_, err := sm.redis.Execute(func(rdb redis.UniversalClient) (any, error) {
			pubsub = rdb.Subscribe(r.Context(), "gw:mcp:notif:"+orgID)
			return nil, nil
		})
		if err == nil && pubsub != nil {
			defer pubsub.Close()
			redisCh = make(chan []byte, 32)
			go func() {
				defer close(redisCh)
				ch := pubsub.Channel()
				for msg := range ch {
					select {
					case redisCh <- []byte(msg.Payload):
					case <-r.Context().Done():
						return
					default:
					}
				}
			}()
		}
	}

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
		case msg, ok := <-redisCh:
			if !ok {
				redisCh = nil
				continue
			}
			_, _ = fmt.Fprintf(w, "data: %s\n\n", string(msg))
			flusher.Flush()
		case <-ticker.C:
			_, _ = fmt.Fprint(w, ": keepalive\n\n")
			flusher.Flush()
		}
	}
}
