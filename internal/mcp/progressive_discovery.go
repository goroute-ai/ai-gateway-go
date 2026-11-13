package mcp

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
	"github.com/redis/go-redis/v9"
)

var (
	ErrHandleNotFound  = errors.New("mcp: opaque tool handle not found or expired")
	ErrStaleToolHandle = errors.New("mcp: stale tool handle (upstream schema changed)")
	ErrInvalidHandle   = errors.New("mcp: invalid tool handle format")
)

const (
	HandlePrefix   = "tool_hdl_"
	HandleTTL      = 1 * time.Hour
	RedisHdlPrefix = "gw:mcp:hdl:"
)

// ToolHandleRecord stores the binding between a 256-bit opaque handle and a verified tool.
type ToolHandleRecord struct {
	Handle     string    `json:"handle"`
	ToolID     string    `json:"tool_id"`
	ServerID   string    `json:"server_id"`
	ServerSlug string    `json:"server_slug"`
	ToolName   string    `json:"tool_name"`
	SchemaHash string    `json:"schema_hash"`
	OrgID      string    `json:"org_id"`
	CreatedAt  time.Time `json:"created_at"`
	ExpiresAt  time.Time `json:"expires_at"`
}

// ProgressiveDiscoveryManager manages progressive tool discovery, opaque handle issuance,
// schema verification, and meta-tool execution.
type ProgressiveDiscoveryManager struct {
	repo        storage.Repository
	redisFabric *storage.RedisFabric
	ttl         time.Duration

	mu       sync.RWMutex
	memStore map[string]*ToolHandleRecord
}

// NewProgressiveDiscoveryManager creates a new ProgressiveDiscoveryManager.
func NewProgressiveDiscoveryManager(repo storage.Repository, redisFabric *storage.RedisFabric, ttl time.Duration) *ProgressiveDiscoveryManager {
	if ttl <= 0 {
		ttl = HandleTTL
	}
	return &ProgressiveDiscoveryManager{
		repo:        repo,
		redisFabric: redisFabric,
		ttl:         ttl,
		memStore:    make(map[string]*ToolHandleRecord),
	}
}

// GenerateHandle issues a new 256-bit opaque handle for the given tool.
func (m *ProgressiveDiscoveryManager) GenerateHandle(ctx context.Context, tool *domain.MCPTool, serverSlug string) (*ToolHandleRecord, error) {
	if tool == nil {
		return nil, errors.New("mcp: tool cannot be nil")
	}

	rawBytes := make([]byte, 32) // 256 bits of entropy
	if _, err := rand.Read(rawBytes); err != nil {
		return nil, fmt.Errorf("mcp: generate random handle: %w", err)
	}

	hdl := HandlePrefix + hex.EncodeToString(rawBytes)
	now := time.Now().UTC()
	record := &ToolHandleRecord{
		Handle:     hdl,
		ToolID:     tool.ID,
		ServerID:   tool.ServerID,
		ServerSlug: serverSlug,
		ToolName:   tool.Name,
		SchemaHash: tool.ToolDefHash,
		OrgID:      tool.OrgID,
		CreatedAt:  now,
		ExpiresAt:  now.Add(m.ttl),
	}

	recordJSON, _ := json.Marshal(record)

	// Persist to Redis Fabric if available
	if m.redisFabric != nil {
		_, err := m.redisFabric.Execute(func(rdb redis.UniversalClient) (any, error) {
			return rdb.Set(ctx, RedisHdlPrefix+hdl, recordJSON, m.ttl).Result()
		})
		if err == nil {
			return record, nil
		}
	}

	// In-memory fallback
	m.mu.Lock()
	m.memStore[hdl] = record
	m.mu.Unlock()

	return record, nil
}

// ResolveHandle resolves an opaque handle and verifies schema freshness against the repository.
func (m *ProgressiveDiscoveryManager) ResolveHandle(ctx context.Context, handle string) (*ToolHandleRecord, *domain.MCPTool, error) {
	handle = strings.TrimSpace(handle)
	if !strings.HasPrefix(handle, HandlePrefix) {
		return nil, nil, ErrInvalidHandle
	}

	var record *ToolHandleRecord

	// 1. Try Redis
	if m.redisFabric != nil {
		rawVal, err := m.redisFabric.Execute(func(rdb redis.UniversalClient) (any, error) {
			return rdb.Get(ctx, RedisHdlPrefix+handle).Result()
		})
		if err == nil {
			if s, ok := rawVal.(string); ok && s != "" {
				var rec ToolHandleRecord
				if err := json.Unmarshal([]byte(s), &rec); err == nil {
					record = &rec
				}
			}
		}
	}

	// 2. Fallback to memory
	if record == nil {
		m.mu.RLock()
		memRec, exists := m.memStore[handle]
		m.mu.RUnlock()
		if exists && time.Now().Before(memRec.ExpiresAt) {
			record = memRec
		}
	}

	if record == nil {
		return nil, nil, ErrHandleNotFound
	}

	// 3. Fetch tool from repository to check freshness (Fail-Closed verification)
	tool, err := m.repo.GetMCPTool(ctx, record.ToolID)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: tool not found in repository", ErrHandleNotFound)
	}

	if tool.ToolDefHash != record.SchemaHash {
		return nil, nil, fmt.Errorf("%w: handle schema hash %s does not match repository hash %s", ErrStaleToolHandle, record.SchemaHash, tool.ToolDefHash)
	}

	return record, tool, nil
}

// ToolSummary is the lightweight metadata returned by progressive search_tools.
type ToolSummary struct {
	Name        string `json:"name"`
	ServerSlug  string `json:"server_slug"`
	Description string `json:"description"`
	ToolHandle  string `json:"tool_handle"`
}

// SearchTools searches available tools and issues progressive handles.
func (m *ProgressiveDiscoveryManager) SearchTools(ctx context.Context, idCtx *domain.IdentityContext, query string, limit int) ([]ToolSummary, error) {
	if limit <= 0 || limit > 50 {
		limit = 10
	}

	orgID := ""
	if idCtx != nil {
		orgID = idCtx.OrgID
	}

	servers, err := m.repo.ListMCPServers(ctx, orgID)
	if err != nil {
		return nil, err
	}

	qLower := strings.ToLower(strings.TrimSpace(query))
	var results []ToolSummary

	for _, srv := range servers {
		if !srv.IsActive {
			continue
		}

		tools, err := m.repo.ListMCPTools(ctx, srv.ID)
		if err != nil {
			continue
		}

		for _, t := range tools {
			if !t.IsActive {
				continue
			}

			// Match query if provided
			if qLower != "" {
				matchName := strings.Contains(strings.ToLower(t.Name), qLower)
				matchDesc := strings.Contains(strings.ToLower(t.Description), qLower)
				matchSrv := strings.Contains(strings.ToLower(srv.Slug), qLower)
				if !matchName && !matchDesc && !matchSrv {
					continue
				}
			}

			// Issue opaque handle for this tool
			rec, err := m.GenerateHandle(ctx, t, srv.Slug)
			if err != nil {
				continue
			}

			results = append(results, ToolSummary{
				Name:        t.Name,
				ServerSlug:  srv.Slug,
				Description: t.Description,
				ToolHandle:  rec.Handle,
			})

			if len(results) >= limit {
				return results, nil
			}
		}
	}

	return results, nil
}

// RegistryFeedEntry defines an entry in the /v1/goroute/mcp/registry feed.
type RegistryFeedEntry struct {
	ServerSlug      string        `json:"server_slug"`
	ServerName      string        `json:"server_name"`
	TransportType   string        `json:"transport_type"`
	ProtocolVersion string        `json:"protocol_version"`
	EndpointURL     string        `json:"endpoint_url"`
	ToolCount       int           `json:"tool_count"`
	Tools           []ToolSummary `json:"tools,omitempty"`
}

// BuildRegistryFeed compiles the enterprise catalog registry feed.
func (m *ProgressiveDiscoveryManager) BuildRegistryFeed(ctx context.Context, idCtx *domain.IdentityContext) ([]RegistryFeedEntry, error) {
	orgID := ""
	if idCtx != nil {
		orgID = idCtx.OrgID
	}

	servers, err := m.repo.ListMCPServers(ctx, orgID)
	if err != nil {
		return nil, err
	}

	var feed []RegistryFeedEntry
	for _, srv := range servers {
		if !srv.IsActive {
			continue
		}
		tools, _ := m.repo.ListMCPTools(ctx, srv.ID)
		activeToolCount := 0
		var summaries []ToolSummary
		for _, t := range tools {
			if t.IsActive {
				activeToolCount++
				rec, err := m.GenerateHandle(ctx, t, srv.Slug)
				if err == nil {
					summaries = append(summaries, ToolSummary{
						Name:        t.Name,
						ServerSlug:  srv.Slug,
						Description: t.Description,
						ToolHandle:  rec.Handle,
					})
				}
			}
		}

		feed = append(feed, RegistryFeedEntry{
			ServerSlug:      srv.Slug,
			ServerName:      srv.Name,
			TransportType:   srv.TransportType,
			ProtocolVersion: srv.ProtocolVersion,
			EndpointURL:     srv.EndpointURL,
			ToolCount:       activeToolCount,
			Tools:           summaries,
		})
	}

	return feed, nil
}
