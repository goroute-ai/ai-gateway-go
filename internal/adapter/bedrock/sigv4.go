package bedrock

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"
)

// SigV4Signer signs HTTP requests with AWS Signature Version 4.
type SigV4Signer struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
	Region          string
	Service         string
}

// Sign signs the given HTTP request in-place using AWS SigV4.
func (s *SigV4Signer) Sign(req *http.Request, payload []byte, signTime time.Time) error {
	if s.AccessKeyID == "" || s.SecretAccessKey == "" {
		return fmt.Errorf("aws credentials missing access key id or secret access key")
	}
	if s.Region == "" {
		s.Region = "us-east-1"
	}
	if s.Service == "" {
		s.Service = "bedrock"
	}

	amzDate := signTime.UTC().Format("20060102T150405Z")
	dateStamp := signTime.UTC().Format("20060102")

	req.Header.Set("x-amz-date", amzDate)
	if s.SessionToken != "" {
		req.Header.Set("x-amz-security-token", s.SessionToken)
	}

	// Payload SHA256
	h := sha256.New()
	h.Write(payload)
	payloadHash := hex.EncodeToString(h.Sum(nil))
	req.Header.Set("x-amz-content-sha256", payloadHash)

	// Collect headers to sign
	headersToSign := make(map[string]string)
	headersToSign["host"] = req.Host
	if req.Host == "" && req.URL != nil {
		headersToSign["host"] = req.URL.Host
	}
	headersToSign["x-amz-date"] = amzDate
	headersToSign["x-amz-content-sha256"] = payloadHash
	if s.SessionToken != "" {
		headersToSign["x-amz-security-token"] = s.SessionToken
	}
	if ct := req.Header.Get("Content-Type"); ct != "" {
		headersToSign["content-type"] = ct
	}

	// Sorted signed header keys
	var sortedKeys []string
	for k := range headersToSign {
		sortedKeys = append(sortedKeys, strings.ToLower(k))
	}
	sort.Strings(sortedKeys)

	var canonicalHeaders strings.Builder
	for _, k := range sortedKeys {
		canonicalHeaders.WriteString(k)
		canonicalHeaders.WriteString(":")
		canonicalHeaders.WriteString(strings.TrimSpace(headersToSign[k]))
		canonicalHeaders.WriteString("\n")
	}
	signedHeaders := strings.Join(sortedKeys, ";")

	// Canonical URI
	canonicalURI := req.URL.EscapedPath()
	if canonicalURI == "" {
		canonicalURI = "/"
	}

	// Canonical Query String
	canonicalQuery := req.URL.RawQuery

	// Canonical Request
	canonicalRequest := fmt.Sprintf("%s\n%s\n%s\n%s\n%s\n%s",
		req.Method,
		canonicalURI,
		canonicalQuery,
		canonicalHeaders.String(),
		signedHeaders,
		payloadHash,
	)

	// Hash Canonical Request
	hReq := sha256.New()
	hReq.Write([]byte(canonicalRequest))
	canonicalRequestHash := hex.EncodeToString(hReq.Sum(nil))

	// Credential Scope
	credentialScope := fmt.Sprintf("%s/%s/%s/aws4_request", dateStamp, s.Region, s.Service)

	// String to Sign
	stringToSign := fmt.Sprintf("AWS4-HMAC-SHA256\n%s\n%s\n%s",
		amzDate,
		credentialScope,
		canonicalRequestHash,
	)

	// Derive signing key
	kSigning := getSignatureKey(s.SecretAccessKey, dateStamp, s.Region, s.Service)

	// Calculate signature
	hSig := hmac.New(sha256.New, kSigning)
	hSig.Write([]byte(stringToSign))
	signature := hex.EncodeToString(hSig.Sum(nil))

	// Build Authorization header
	authHeader := fmt.Sprintf("AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		s.AccessKeyID,
		credentialScope,
		signedHeaders,
		signature,
	)
	req.Header.Set("Authorization", authHeader)
	return nil
}

func hmacSHA256(key []byte, data string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(data))
	return h.Sum(nil)
}

func getSignatureKey(key, dateStamp, regionName, serviceName string) []byte {
	kDate := hmacSHA256([]byte("AWS4"+key), dateStamp)
	kRegion := hmacSHA256(kDate, regionName)
	kService := hmacSHA256(kRegion, serviceName)
	kSigning := hmacSHA256(kService, "aws4_request")
	return kSigning
}
