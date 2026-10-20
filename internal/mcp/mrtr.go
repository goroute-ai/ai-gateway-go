package mcp

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/goroute-ai/ai-gateway-go/internal/auth"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
	"github.com/redis/go-redis/v9"
)

// MRTRClaims contains authenticated identity and security parameters bound to an MCP Round-Trip Token.
type MRTRClaims struct {
	JTI            string `json:"jti"`
	OrgID          string `json:"org_id"`
	KeyPrefix      string `json:"key_prefix"`
	UserID         string `json:"user_id,omitempty"`
	CallingAgentID string `json:"calling_agent_id,omitempty"`
	Method         string `json:"method"`
	ParamsSHA256   string `json:"params_sha256"`
	IssuedAt       int64  `json:"iat"`
	ExpiresAt      int64  `json:"exp"`
}

// MRTRManager handles issuance, encryption, verification, and single-use anti-replay enforcement of MRTR tokens.
type MRTRManager struct {
	vault       *auth.Vault
	redis       *storage.RedisFabric
	keyID       string
	memMu       sync.Mutex
	memUsedJTIs map[string]time.Time // in-memory fallback for anti-replay if Redis is unavailable
}

// NewMRTRManager creates a new MRTR manager.
func NewMRTRManager(vault *auth.Vault, redis *storage.RedisFabric, keyID string) *MRTRManager {
	if keyID == "" {
		keyID = "mrtr_v1"
	}
	return &MRTRManager{
		vault:       vault,
		redis:       redis,
		keyID:       keyID,
		memUsedJTIs: make(map[string]time.Time),
	}
}

// IssueToken mints an AEAD-encrypted single-use MRTR token bound to caller identity and payload hash.
func (m *MRTRManager) IssueToken(
	ctx context.Context,
	idCtx *domain.IdentityContext,
	method string,
	params []byte,
	ttl time.Duration,
) (string, error) {
	if idCtx == nil {
		return "", errors.New("mrtr: identity context required")
	}
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}

	now := time.Now().UTC()
	var paramsHash string
	if len(params) > 0 {
		h := sha256.Sum256(params)
		paramsHash = hex.EncodeToString(h[:])
	}

	claims := MRTRClaims{
		JTI:          "mrtr_" + uuid.NewString(),
		OrgID:        idCtx.OrgID,
		KeyPrefix:    idCtx.KeyPrefix,
		UserID:       idCtx.UserID,
		Method:       method,
		ParamsSHA256: paramsHash,
		IssuedAt:     now.UnixMilli(),
		ExpiresAt:    now.Add(ttl).UnixMilli(),
	}

	claimsBytes, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("mrtr: marshal claims: %w", err)
	}

	// Encrypt claims using AEAD Vault
	ciphertext, dek, err := m.vault.EncryptString(string(claimsBytes))
	if err != nil {
		return "", fmt.Errorf("mrtr: encrypt claims: %w", err)
	}

	// Payload pack: dek + "." + ciphertext
	pack := dek + "." + ciphertext
	tokenStr := fmt.Sprintf("v1.%s.%s", m.keyID, base64.RawURLEncoding.EncodeToString([]byte(pack)))
	return tokenStr, nil
}

// VerifyAndConsumeToken validates the token integrity, caller binding, parameter integrity,
// and enforces single-use replay protection.
func (m *MRTRManager) VerifyAndConsumeToken(
	ctx context.Context,
	tokenStr string,
	idCtx *domain.IdentityContext,
	method string,
	params []byte,
) (*MRTRClaims, error) {
	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 || parts[0] != "v1" {
		return nil, &JSONRPCError{
			Code:    CodeInvalidParams,
			Message: "invalid mrtr token format",
		}
	}

	rawPack, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, &JSONRPCError{
			Code:    CodeInvalidParams,
			Message: "corrupted mrtr token encoding",
		}
	}

	packParts := strings.SplitN(string(rawPack), ".", 2)
	if len(packParts) != 2 {
		return nil, &JSONRPCError{
			Code:    CodeInvalidParams,
			Message: "corrupted mrtr token payload",
		}
	}

	dek := packParts[0]
	ciphertext := packParts[1]

	plainJSON, err := m.vault.DecryptString(ciphertext, dek)
	if err != nil {
		return nil, &JSONRPCError{
			Code:    CodeInvalidParams,
			Message: "mrtr token decryption failed or tamper detected",
		}
	}

	var claims MRTRClaims
	if err := json.Unmarshal([]byte(plainJSON), &claims); err != nil {
		return nil, &JSONRPCError{
			Code:    CodeInvalidParams,
			Message: "mrtr token claims unmarshal error",
		}
	}

	// Expiration check
	now := time.Now().UTC().UnixMilli()
	if now > claims.ExpiresAt {
		return nil, &JSONRPCError{
			Code:    CodeInvalidParams,
			Message: "mrtr token has expired",
		}
	}

	// Caller identity binding checks
	if idCtx != nil {
		if claims.OrgID != "" && idCtx.OrgID != "" && claims.OrgID != idCtx.OrgID {
			return nil, &JSONRPCError{
				Code:    CodeInvalidRequest,
				Message: "Forbidden: mrtr token org mismatch",
			}
		}
		if claims.KeyPrefix != "" && idCtx.KeyPrefix != "" && claims.KeyPrefix != idCtx.KeyPrefix {
			return nil, &JSONRPCError{
				Code:    CodeInvalidRequest,
				Message: "Forbidden: mrtr token key prefix mismatch",
			}
		}
	}

	// Method check
	if method != "" && claims.Method != "" && claims.Method != method {
		return nil, &JSONRPCError{
			Code:    CodeInvalidParams,
			Message: fmt.Sprintf("mrtr token method mismatch: expected %s, got %s", claims.Method, method),
		}
	}

	// Parameters hash check
	if claims.ParamsSHA256 != "" && len(params) > 0 {
		h := sha256.Sum256(params)
		actualHash := hex.EncodeToString(h[:])
		if actualHash != claims.ParamsSHA256 {
			return nil, &JSONRPCError{
				Code:    CodeInvalidParams,
				Message: "mrtr token parameters tamper detected: payload hash mismatch",
			}
		}
	}

	// Anti-Replay: Ensure single-use via Redis SetNX or in-memory fallback
	ttlMs := claims.ExpiresAt - now
	if ttlMs <= 0 {
		ttlMs = 1000
	}
	ttl := time.Duration(ttlMs) * time.Millisecond

	isReplay := false
	if m.redis != nil {
		res, err := m.redis.Execute(func(rdb *redis.Client) (any, error) {
			return rdb.SetNX(ctx, "gw:mcp:mrtr:jti:"+claims.JTI, "used", ttl).Result()
		})
		if err == nil {
			if ok, _ := res.(bool); !ok {
				isReplay = true
			}
		}
	} else {
		m.memMu.Lock()
		if exp, exists := m.memUsedJTIs[claims.JTI]; exists && time.Now().Before(exp) {
			isReplay = true
		} else {
			m.memUsedJTIs[claims.JTI] = time.Now().Add(ttl)
		}
		m.memMu.Unlock()
	}

	if isReplay {
		return nil, &JSONRPCError{
			Code:    CodeInvalidRequest,
			Message: "mrtr token replay detected: token has already been consumed",
		}
	}

	return &claims, nil
}
