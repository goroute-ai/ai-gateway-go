package a2a

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/goroute-ai/ai-gateway-go/internal/a2a/pb"
	"github.com/goroute-ai/ai-gateway-go/internal/auth"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
	"google.golang.org/protobuf/encoding/protojson"
)

// CanonicalizeJCS serializes any JSON-compatible object into RFC 8785 JSON Canonicalization Scheme (JCS).
func CanonicalizeJCS(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var parsed any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&parsed); err != nil {
		return nil, err
	}
	return canonicalizeValue(parsed)
}

func canonicalizeValue(v any) ([]byte, error) {
	switch val := v.(type) {
	case nil:
		return []byte("null"), nil
	case bool:
		if val {
			return []byte("true"), nil
		}
		return []byte("false"), nil
	case json.Number:
		return []byte(val.String()), nil
	case string:
		return json.Marshal(val)
	case []any:
		var buf bytes.Buffer
		buf.WriteByte('[')
		for i, item := range val {
			if i > 0 {
				buf.WriteByte(',')
			}
			b, err := canonicalizeValue(item)
			if err != nil {
				return nil, err
			}
			buf.Write(b)
		}
		buf.WriteByte(']')
		return buf.Bytes(), nil
	case map[string]any:
		keys := make([]string, 0, len(val))
		for k := range val {
			keys = append(keys, k)
		}
		// RFC 8785 sorts keys by UTF-16 code units (lexicographical byte sort is equivalent for standard UTF-8)
		sort.Strings(keys)

		var buf bytes.Buffer
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			kb, _ := json.Marshal(k)
			buf.Write(kb)
			buf.WriteByte(':')
			vb, err := canonicalizeValue(val[k])
			if err != nil {
				return nil, err
			}
			buf.Write(vb)
		}
		buf.WriteByte('}')
		return buf.Bytes(), nil
	default:
		return json.Marshal(val)
	}
}

// UpstreamCardVerifier validates upstream AgentCard signatures against trusted JWKS keys.
type UpstreamCardVerifier struct {
	trustedPublicKeys map[string]any // kid -> *ecdsa.PublicKey, *rsa.PublicKey, or ed25519.PublicKey
}

// NewUpstreamCardVerifier creates a new verifier with an initial map of trusted public keys.
func NewUpstreamCardVerifier(trustedKeys map[string]any) *UpstreamCardVerifier {
	if trustedKeys == nil {
		trustedKeys = make(map[string]any)
	}
	return &UpstreamCardVerifier{trustedPublicKeys: trustedKeys}
}

// AddTrustedKey registers a trusted public key for an upstream agent's key ID.
func (v *UpstreamCardVerifier) AddTrustedKey(kid string, pubKey any) {
	v.trustedPublicKeys[kid] = pubKey
}

// VerifyAgentCard checks the detached or embedded JWS signature of an AgentCard.
func (v *UpstreamCardVerifier) VerifyAgentCard(card *pb.AgentCard, rawJWS string) error {
	if card == nil {
		return errors.New("a2a: nil agent card")
	}

	parts := strings.Split(rawJWS, ".")
	if len(parts) != 3 {
		return errors.New("a2a: invalid jws compact serialization format")
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return fmt.Errorf("a2a: decode jws header: %w", err)
	}

	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return fmt.Errorf("a2a: parse jws header: %w", err)
	}

	if header.Kid == "" {
		return errors.New("a2a: jws header missing mandatory kid")
	}

	pubKey, ok := v.trustedPublicKeys[header.Kid]
	if !ok || pubKey == nil {
		return fmt.Errorf("a2a: untrusted signing key id %q", header.Kid)
	}

	// Canonicalize payload per RFC 8785
	cardJSON, err := protojson.Marshal(card)
	if err != nil {
		return fmt.Errorf("a2a: marshal agent card: %w", err)
	}
	var cardMap map[string]any
	_ = json.Unmarshal(cardJSON, &cardMap)
	// Strip signatures property before verification
	delete(cardMap, "signatures")

	canonicalCard, err := CanonicalizeJCS(cardMap)
	if err != nil {
		return fmt.Errorf("a2a: canonicalize card: %w", err)
	}

	// Verify signing input: parts[0] + "." + base64url(canonicalCard)
	expectedPayloadB64 := base64.RawURLEncoding.EncodeToString(canonicalCard)
	if parts[1] != "" && parts[1] != expectedPayloadB64 {
		return errors.New("a2a: jws payload does not match canonical agent card")
	}

	sigInput := parts[0] + "." + expectedPayloadB64
	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return fmt.Errorf("a2a: decode signature: %w", err)
	}

	h := sha256.Sum256([]byte(sigInput))

	switch header.Alg {
	case "ES256":
		ecKey, ok := pubKey.(*ecdsa.PublicKey)
		if !ok {
			return errors.New("a2a: key type mismatch for ES256")
		}
		if !ecdsa.VerifyASN1(ecKey, h[:], sigBytes) {
			return errors.New("a2a: ES256 signature verification failed")
		}
	case "RS256":
		rsaKey, ok := pubKey.(*rsa.PublicKey)
		if !ok {
			return errors.New("a2a: key type mismatch for RS256")
		}
		if err := rsa.VerifyPKCS1v15(rsaKey, 0, h[:], sigBytes); err != nil {
			return fmt.Errorf("a2a: RS256 signature verification failed: %w", err)
		}
	case "EdDSA":
		edKey, ok := pubKey.(ed25519.PublicKey)
		if !ok {
			return errors.New("a2a: key type mismatch for EdDSA")
		}
		if !ed25519.Verify(edKey, []byte(sigInput), sigBytes) {
			return errors.New("a2a: EdDSA signature verification failed")
		}
	default:
		return fmt.Errorf("a2a: unsupported signature algorithm %q", header.Alg)
	}

	return nil
}

// GatewayCardSigner signs rewritten AgentCards using Gateway private keys (Vault/KMS).
type GatewayCardSigner struct {
	keyID      string
	alg        string
	privateKey any // *ecdsa.PrivateKey, *rsa.PrivateKey, or ed25519.PrivateKey
	vault      *auth.Vault
}

// NewGatewayCardSigner initializes a GatewayCardSigner.
func NewGatewayCardSigner(keyID, alg string, privKey any, vault *auth.Vault) *GatewayCardSigner {
	if keyID == "" {
		keyID = "gw-a2a-v1"
	}
	if alg == "" {
		alg = "ES256"
	}
	return &GatewayCardSigner{
		keyID:      keyID,
		alg:        alg,
		privateKey: privKey,
		vault:      vault,
	}
}

// RewriteAndSignAgentCard strips upstream signatures, rewrites interface URLs to the gateway namespace,
// canonicalizes via JCS, and signs the card with Gateway credentials.
func (s *GatewayCardSigner) RewriteAndSignAgentCard(
	card *pb.AgentCard,
	gatewayBaseURL string,
	agentSlug string,
) (*pb.AgentCard, string, error) {
	if card == nil {
		return nil, "", errors.New("a2a: nil agent card")
	}

	// Clone card by marshalling and unmarshalling
	cardJSON, err := protojson.Marshal(card)
	if err != nil {
		return nil, "", err
	}
	var cardMap map[string]any
	_ = json.Unmarshal(cardJSON, &cardMap)

	// Strip upstream signatures
	delete(cardMap, "signatures")

	// Rewrite interface endpoints to point to the Gateway's namespaced proxy
	namespacedBase := fmt.Sprintf("%s/a2a/v1/agents/%s", strings.TrimRight(gatewayBaseURL, "/"), agentSlug)
	if ifaces, ok := cardMap["supportedInterfaces"].([]any); ok {
		for _, ifaceRaw := range ifaces {
			if ifaceMap, ok := ifaceRaw.(map[string]any); ok {
				ifaceMap["url"] = namespacedBase
			}
		}
	} else {
		// Provide default interface pointing to gateway
		cardMap["supportedInterfaces"] = []any{
			map[string]any{
				"protocolBinding": "HTTP+JSON",
				"url":             namespacedBase,
			},
		}
	}

	// Canonicalize via RFC 8785
	canonicalBytes, err := CanonicalizeJCS(cardMap)
	if err != nil {
		return nil, "", fmt.Errorf("a2a: canonicalize rewritten card: %w", err)
	}

	// Sign payload
	headerMap := map[string]string{
		"alg": s.alg,
		"kid": s.keyID,
		"typ": "JWT",
	}
	headerJSON, _ := json.Marshal(headerMap)
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	payloadB64 := base64.RawURLEncoding.EncodeToString(canonicalBytes)
	sigInput := headerB64 + "." + payloadB64

	sigBytes, err := s.signDigest(sigInput)
	if err != nil {
		return nil, "", fmt.Errorf("a2a: sign card: %w", err)
	}
	sigB64 := base64.RawURLEncoding.EncodeToString(sigBytes)
	jwsCompact := fmt.Sprintf("%s.%s.%s", headerB64, payloadB64, sigB64)

	// Attach gateway signature to cardMap
	cardMap["signatures"] = []any{
		map[string]any{
			"header":    headerMap,
			"signature": sigB64,
		},
	}

	// Re-serialize to protobuf
	signedJSON, _ := json.Marshal(cardMap)
	var signedCard pb.AgentCard
	if err := protojson.Unmarshal(signedJSON, &signedCard); err != nil {
		return nil, "", fmt.Errorf("a2a: re-unmarshal signed card: %w", err)
	}

	return &signedCard, jwsCompact, nil
}

func (s *GatewayCardSigner) signDigest(sigInput string) ([]byte, error) {
	if s.privateKey == nil {
		// Generate ephemeral ECDSA P-256 key if none provided
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		s.privateKey = key
	}

	h := sha256.Sum256([]byte(sigInput))

	switch k := s.privateKey.(type) {
	case *ecdsa.PrivateKey:
		return ecdsa.SignASN1(rand.Reader, k, h[:])
	case ed25519.PrivateKey:
		return ed25519.Sign(k, []byte(sigInput)), nil
	default:
		return nil, errors.New("a2a: unsupported private key type for signing")
	}
}

// ServeWellKnownAgentCard serves `GET /.well-known/agent-card.json`.
func ServeWellKnownAgentCard(
	w http.ResponseWriter,
	r *http.Request,
	repo storage.Repository,
	signer *GatewayCardSigner,
	gatewayBaseURL string,
	defaultAgentSlug string,
) {
	agentSlug := r.URL.Query().Get("agent")
	if agentSlug == "" {
		agentSlug = r.URL.Query().Get("slug")
	}
	if agentSlug == "" {
		agentSlug = defaultAgentSlug
	}
	if agentSlug == "" {
		agents, _ := repo.ListA2AAgents(r.Context(), "")
		if len(agents) > 0 {
			agentSlug = agents[0].Slug
		}
	}
	if agentSlug == "" {
		card := &pb.AgentCard{
			Name:        "GoRoute AI Gateway Agent Service",
			Description: "Enterprise Linux Foundation A2A v1.0 Gateway Hub",
			Version:     "1.0.0",
			SupportedInterfaces: []*pb.AgentInterface{
				{
					ProtocolBinding: "HTTP+JSON",
					Url:             gatewayBaseURL + "/a2a/v1/agents",
				},
				{
					ProtocolBinding: "JSON-RPC",
					Url:             gatewayBaseURL + "/a2a/v1/agents",
				},
			},
		}
		rawBytes, _ := protojson.Marshal(card)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(rawBytes)
		return
	}

	agent, err := repo.GetA2AAgentBySlug(r.Context(), "", agentSlug)
	if err != nil || agent == nil || !agent.IsActive {
		http.Error(w, fmt.Sprintf("A2A Agent %q not found", agentSlug), http.StatusNotFound)
		return
	}

	// Decode registered agent card
	var card pb.AgentCard
	if len(agent.AgentCardJSON) > 0 {
		_ = protojson.Unmarshal([]byte(agent.AgentCardJSON), &card)
	} else {
		// Provide default minimal agent card
		card = pb.AgentCard{
			Name:    agent.Name,
			Version: "1.0.0",
		}
	}

	// Rewrite & Sign using Gateway key
	signedCard, _, err := signer.RewriteAndSignAgentCard(&card, gatewayBaseURL, agent.Slug)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to sign agent card: %v", err), http.StatusInternalServerError)
		return
	}

	outJSON, err := protojson.Marshal(signedCard)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(outJSON)
}
