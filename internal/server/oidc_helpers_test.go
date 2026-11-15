package server_test

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/auth"
)

var (
	serverTestRSAOnce sync.Once
	serverTestRSAKey  *rsa.PrivateKey
	serverTestRSAErr  error
)

func initServerTestRSAKey() {
	serverTestRSAOnce.Do(func() {
		serverTestRSAKey, serverTestRSAErr = rsa.GenerateKey(rand.Reader, 2048)
	})
}

type serverTestOIDCIssuer struct {
	t      *testing.T
	server *httptest.Server
	rsaKey *rsa.PrivateKey
	kid    string
}

func newServerTestOIDCIssuer(t *testing.T) *serverTestOIDCIssuer {
	t.Helper()
	initServerTestRSAKey()
	if serverTestRSAErr != nil {
		t.Fatalf("generate rsa key: %v", serverTestRSAErr)
	}
	iss := &serverTestOIDCIssuer{
		t:      t,
		rsaKey: serverTestRSAKey,
		kid:    "srv-test-rsa-1",
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                           iss.server.URL,
			"jwks_uri":                         iss.server.URL + "/protocol/openid-connect/certs",
			"authorization_endpoint":           iss.server.URL + "/protocol/openid-connect/auth",
			"token_endpoint":                   iss.server.URL + "/protocol/openid-connect/token",
			"userinfo_endpoint":                iss.server.URL + "/protocol/openid-connect/userinfo",
			"end_session_endpoint":             iss.server.URL + "/protocol/openid-connect/logout",
			"code_challenge_methods_supported": []string{"S256"},
		})
	})
	mux.HandleFunc("/protocol/openid-connect/certs", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]any{{
				"kty":     "RSA",
				"kid":     iss.kid,
				"use":     "sig",
				"key_ops": []string{"verify"},
				"n":       base64.RawURLEncoding.EncodeToString(iss.rsaKey.N.Bytes()),
				"e":       base64.RawURLEncoding.EncodeToString(big.NewInt(int64(iss.rsaKey.E)).Bytes()),
			}},
		})
	})

	iss.server = httptest.NewServer(mux)
	t.Cleanup(iss.server.Close)
	return iss
}

func (i *serverTestOIDCIssuer) Issuer() string { return i.server.URL }
func (i *serverTestOIDCIssuer) JWKSURL() string {
	return i.server.URL + "/protocol/openid-connect/certs"
}
func (i *serverTestOIDCIssuer) DiscoveryURL() string {
	return i.server.URL + "/.well-known/openid-configuration"
}

func (i *serverTestOIDCIssuer) SignClaims(claims *auth.JWTClaims) string {
	i.t.Helper()
	if claims == nil {
		claims = &auth.JWTClaims{}
	}
	payload := map[string]any{
		"sub": claims.Subject,
	}
	if claims.Issuer != "" {
		payload["iss"] = claims.Issuer
	} else {
		payload["iss"] = i.Issuer()
	}
	if len(claims.Audience) == 1 {
		payload["aud"] = claims.Audience[0]
	} else if len(claims.Audience) > 1 {
		payload["aud"] = []string(claims.Audience)
	}
	if claims.ExpiresAt != 0 {
		payload["exp"] = claims.ExpiresAt
	} else {
		payload["exp"] = time.Now().UTC().Add(time.Hour).Unix()
	}
	if claims.NotBefore != 0 {
		payload["nbf"] = claims.NotBefore
	}
	if claims.IssuedAt != 0 {
		payload["iat"] = claims.IssuedAt
	} else {
		payload["iat"] = time.Now().UTC().Unix()
	}
	if claims.Email != "" {
		payload["email"] = claims.Email
	}
	if claims.Role != "" {
		payload["role"] = claims.Role
	}
	if claims.OrgID != "" {
		payload["org_id"] = claims.OrgID
	}
	if len(claims.TeamIDs) > 0 {
		payload["team_ids"] = claims.TeamIDs
	}
	if claims.EndUserID != "" {
		payload["end_user_id"] = claims.EndUserID
	}
	for k, v := range claims.RawClaims {
		payload[k] = v
	}

	hdrBytes, _ := json.Marshal(map[string]any{
		"alg": "RS256",
		"typ": "JWT",
		"kid": i.kid,
	})
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		i.t.Fatalf("marshal jwt claims: %v", err)
	}
	signingInput := base64.RawURLEncoding.EncodeToString(hdrBytes) + "." + base64.RawURLEncoding.EncodeToString(payloadBytes)
	digest := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, i.rsaKey, crypto.SHA256, digest[:])
	if err != nil {
		i.t.Fatalf("sign rsa jwt: %v", err)
	}
	return fmt.Sprintf("%s.%s", signingInput, base64.RawURLEncoding.EncodeToString(sig))
}
