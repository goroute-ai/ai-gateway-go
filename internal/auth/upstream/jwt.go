package upstream

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"
)

var (
	ErrUntrustedAudience = errors.New("upstream jwt: target audience is not in trusted audiences list")
	ErrMissingSigningKey = errors.New("upstream jwt: signing key is required")
)

// JWTStrategy generates and signs short-lived JWT tokens for upstream service identity.
type JWTStrategy struct {
	KeyID            string        `json:"key_id"`
	SigningKey       string        `json:"-"` // Secret key
	Issuer           string        `json:"issuer"`
	TrustedAudiences []string      `json:"trusted_audiences"`
	TokenTTL         time.Duration `json:"token_ttl"`
	HeaderName       string        `json:"header_name"`
}

// NewJWTStrategy constructs a JWTStrategy.
func NewJWTStrategy(keyID, signingKey, issuer string, trustedAudiences []string, ttl time.Duration) (*JWTStrategy, error) {
	if strings.TrimSpace(signingKey) == "" {
		return nil, ErrMissingSigningKey
	}
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	return &JWTStrategy{
		KeyID:            keyID,
		SigningKey:       signingKey,
		Issuer:           issuer,
		TrustedAudiences: trustedAudiences,
		TokenTTL:         ttl,
		HeaderName:       "Authorization",
	}, nil
}

func (s *JWTStrategy) Type() string {
	return "vault_jwt"
}

func (s *JWTStrategy) Apply(ctx context.Context, req *http.Request, authCtx *UpstreamAuthContext) error {
	if req == nil {
		return fmt.Errorf("upstream jwt auth: nil request")
	}

	audience := ""
	if authCtx != nil {
		audience = authCtx.TargetURL
		if audience == "" {
			audience = authCtx.ServerSlug
		}
	}
	if audience == "" {
		audience = req.URL.String()
	}

	// Validate target audience against trusted audiences
	if len(s.TrustedAudiences) > 0 {
		trusted := false
		for _, ta := range s.TrustedAudiences {
			if ta == "*" || ta == audience || strings.HasPrefix(audience, ta) {
				trusted = true
				break
			}
		}
		if !trusted {
			return fmt.Errorf("%w: %q (allowed: %v)", ErrUntrustedAudience, audience, s.TrustedAudiences)
		}
	}

	now := time.Now().UTC()
	headerMap := map[string]string{
		"alg": "HS256",
		"typ": "JWT",
		"kid": s.KeyID,
	}
	headerBytes, _ := json.Marshal(headerMap)

	claimsMap := map[string]any{
		"iss": s.Issuer,
		"sub": "goroute-ai-gateway",
		"aud": audience,
		"iat": now.Unix(),
		"exp": now.Add(s.TokenTTL).Unix(),
	}
	if authCtx != nil {
		if authCtx.CallingOrgID != "" {
			claimsMap["org_id"] = authCtx.CallingOrgID
		}
		if authCtx.CallingUserID != "" {
			claimsMap["user_id"] = authCtx.CallingUserID
		}
		if authCtx.CallingAgentID != "" {
			claimsMap["agent_id"] = authCtx.CallingAgentID
		}
	}
	claimsBytes, _ := json.Marshal(claimsMap)

	part1 := base64.RawURLEncoding.EncodeToString(headerBytes)
	part2 := base64.RawURLEncoding.EncodeToString(claimsBytes)
	signingInput := part1 + "." + part2

	mac := hmac.New(sha256.New, []byte(s.SigningKey))
	mac.Write([]byte(signingInput))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	jwtToken := signingInput + "." + sig

	headerName := s.HeaderName
	if headerName == "" {
		headerName = "Authorization"
	}
	req.Header.Set(headerName, "Bearer "+jwtToken)
	return nil
}

func (s *JWTStrategy) IsAudienceAllowed(aud string) bool {
	if len(s.TrustedAudiences) == 0 {
		return true
	}
	return slices.Contains(s.TrustedAudiences, "*") || slices.Contains(s.TrustedAudiences, aud)
}
