package auth_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/auth"
	"github.com/goroute-ai/ai-gateway-go/internal/security/network"
)

var (
	testOIDCKeyOnce sync.Once
	testOIDCRSAKey  *rsa.PrivateKey
	testOIDCEC256   *ecdsa.PrivateKey
	testOIDCEC384   *ecdsa.PrivateKey
	testOIDCEC521   *ecdsa.PrivateKey
	testOIDCKeyErr  error
)

func initTestOIDCKeys() {
	testOIDCKeyOnce.Do(func() {
		testOIDCRSAKey, testOIDCKeyErr = rsa.GenerateKey(rand.Reader, 2048)
		if testOIDCKeyErr != nil {
			return
		}
		testOIDCEC256, testOIDCKeyErr = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if testOIDCKeyErr != nil {
			return
		}
		testOIDCEC384, testOIDCKeyErr = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if testOIDCKeyErr != nil {
			return
		}
		testOIDCEC521, testOIDCKeyErr = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	})
}

// testOIDCIssuer serves an ephemeral OIDC Discovery 1.0 + JWKS server backed by asymmetric
// RSA and ECDSA keys for unit tests without symmetric HS256 secrets.
type testOIDCIssuer struct {
	t      *testing.T
	server *httptest.Server
	rsaKey *rsa.PrivateKey
	ec256  *ecdsa.PrivateKey
	ec384  *ecdsa.PrivateKey
	ec521  *ecdsa.PrivateKey
	rsaKid string
	ecKid  string
}

func newTestOIDCIssuer(t *testing.T) *testOIDCIssuer {
	t.Helper()
	initTestOIDCKeys()
	if testOIDCKeyErr != nil {
		t.Fatalf("generate test oidc keys: %v", testOIDCKeyErr)
	}

	iss := &testOIDCIssuer{
		t:      t,
		rsaKey: testOIDCRSAKey,
		ec256:  testOIDCEC256,
		ec384:  testOIDCEC384,
		ec521:  testOIDCEC521,
		rsaKid: "test-rsa-key-1",
		ecKid:  "test-ec-key-1",
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                iss.server.URL,
			"jwks_uri":                              iss.server.URL + "/protocol/openid-connect/certs",
			"authorization_endpoint":                iss.server.URL + "/protocol/openid-connect/auth",
			"token_endpoint":                        iss.server.URL + "/protocol/openid-connect/token",
			"userinfo_endpoint":                     iss.server.URL + "/protocol/openid-connect/userinfo",
			"end_session_endpoint":                  iss.server.URL + "/protocol/openid-connect/logout",
			"revocation_endpoint":                   iss.server.URL + "/protocol/openid-connect/revoke",
			"introspection_endpoint":                iss.server.URL + "/protocol/openid-connect/token/introspect",
			"code_challenge_methods_supported":      []string{"S256"},
			"id_token_signing_alg_values_supported": []string{"RS256", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512"},
		})
	})
	mux.HandleFunc("/protocol/openid-connect/certs", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]any{
				{
					"kty":     "RSA",
					"kid":     iss.rsaKid,
					"use":     "sig",
					"key_ops": []string{"verify"},
					"n":       base64.RawURLEncoding.EncodeToString(iss.rsaKey.N.Bytes()),
					"e":       base64.RawURLEncoding.EncodeToString(big.NewInt(int64(iss.rsaKey.E)).Bytes()),
				},
				encodeECJWK("test-ec-p256", "P-256", &iss.ec256.PublicKey),
				encodeECJWK("test-ec-p384", "P-384", &iss.ec384.PublicKey),
				encodeECJWK("test-ec-p521", "P-521", &iss.ec521.PublicKey),
			},
		})
	})

	iss.server = httptest.NewServer(mux)
	t.Cleanup(iss.server.Close)
	return iss
}

func encodeECJWK(kid, crv string, pub *ecdsa.PublicKey) map[string]any {
	coordSize := (pub.Curve.Params().BitSize + 7) / 8
	xb := pub.X.Bytes()
	yb := pub.Y.Bytes()
	xPadded := make([]byte, coordSize)
	yPadded := make([]byte, coordSize)
	copy(xPadded[coordSize-len(xb):], xb)
	copy(yPadded[coordSize-len(yb):], yb)
	return map[string]any{
		"kty":     "EC",
		"kid":     kid,
		"use":     "sig",
		"key_ops": []string{"verify"},
		"crv":     crv,
		"x":       base64.RawURLEncoding.EncodeToString(xPadded),
		"y":       base64.RawURLEncoding.EncodeToString(yPadded),
	}
}

func (i *testOIDCIssuer) Issuer() string  { return i.server.URL }
func (i *testOIDCIssuer) JWKSURL() string { return i.server.URL + "/protocol/openid-connect/certs" }
func (i *testOIDCIssuer) DiscoveryURL() string {
	return i.server.URL + "/.well-known/openid-configuration"
}

func (i *testOIDCIssuer) NetworkPolicy() *network.Policy {
	return &network.Policy{
		AllowLoopbackHTTP: true,
	}
}

func (i *testOIDCIssuer) JWTConfig(audience string) auth.JWTConfig {
	return auth.JWTConfig{
		Issuer:        i.Issuer(),
		Audience:      audience,
		OIDCJWKSURL:   i.JWKSURL(),
		NetworkPolicy: i.NetworkPolicy(),
	}
}

func (i *testOIDCIssuer) SignClaims(claims *auth.JWTClaims) string {
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
		payload["exp"] = time.Now().Add(time.Hour).Unix()
	}
	if claims.NotBefore != 0 {
		payload["nbf"] = claims.NotBefore
	}
	if claims.IssuedAt != 0 {
		payload["iat"] = claims.IssuedAt
	} else {
		payload["iat"] = time.Now().Unix()
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
	return i.SignWithAlg("RS256", payload)
}

func (i *testOIDCIssuer) SignWithAlg(alg string, claims map[string]any) string {
	i.t.Helper()
	var kid string
	switch alg {
	case "RS256", "PS256", "PS384", "PS512":
		kid = i.rsaKid
	case "ES256":
		kid = "test-ec-p256"
	case "ES384":
		kid = "test-ec-p384"
	case "ES512":
		kid = "test-ec-p521"
	default:
		i.t.Fatalf("unsupported test alg %q", alg)
	}

	hdrBytes, _ := json.Marshal(map[string]any{
		"alg": alg,
		"typ": "JWT",
		"kid": kid,
	})
	payloadBytes, err := json.Marshal(claims)
	if err != nil {
		i.t.Fatalf("marshal test jwt claims: %v", err)
	}

	signingInput := base64.RawURLEncoding.EncodeToString(hdrBytes) + "." + base64.RawURLEncoding.EncodeToString(payloadBytes)

	var sig []byte
	switch alg {
	case "RS256":
		d := sha256.Sum256([]byte(signingInput))
		sig, err = rsa.SignPKCS1v15(rand.Reader, i.rsaKey, crypto.SHA256, d[:])
	case "PS256":
		d := sha256.Sum256([]byte(signingInput))
		sig, err = rsa.SignPSS(rand.Reader, i.rsaKey, crypto.SHA256, d[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
	case "PS384":
		d := sha512.Sum384([]byte(signingInput))
		sig, err = rsa.SignPSS(rand.Reader, i.rsaKey, crypto.SHA384, d[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
	case "PS512":
		d := sha512.Sum512([]byte(signingInput))
		sig, err = rsa.SignPSS(rand.Reader, i.rsaKey, crypto.SHA512, d[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
	case "ES256":
		d := sha256.Sum256([]byte(signingInput))
		sig, err = signECDSAP1363(i.ec256, d[:], 32)
	case "ES384":
		d := sha512.Sum384([]byte(signingInput))
		sig, err = signECDSAP1363(i.ec384, d[:], 48)
	case "ES512":
		d := sha512.Sum512([]byte(signingInput))
		sig, err = signECDSAP1363(i.ec521, d[:], 66)
	}
	if err != nil {
		i.t.Fatalf("sign test jwt %s: %v", alg, err)
	}
	return fmt.Sprintf("%s.%s", signingInput, base64.RawURLEncoding.EncodeToString(sig))
}

func signECDSAP1363(key *ecdsa.PrivateKey, digest []byte, coordSize int) ([]byte, error) {
	r, s, err := ecdsa.Sign(rand.Reader, key, digest)
	if err != nil {
		return nil, err
	}
	out := make([]byte, coordSize*2)
	rb := r.Bytes()
	sb := s.Bytes()
	copy(out[coordSize-len(rb):coordSize], rb)
	copy(out[2*coordSize-len(sb):], sb)
	return out, nil
}

func signHS256TestToken(secret string, claims map[string]any) string {
	_ = strings.TrimSpace(secret)
	hdr, _ := json.Marshal(map[string]any{"alg": "HS256", "typ": "JWT"})
	pl, _ := json.Marshal(claims)
	return base64.RawURLEncoding.EncodeToString(hdr) + "." + base64.RawURLEncoding.EncodeToString(pl) + ".ZmFrZXNpZw"
}
