package upstream

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
)

const (
	emptyPayloadHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)

// SigV4Config holds configuration for AWS SigV4 request signing.
type SigV4Config struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string // Optional: for temporary STS credentials
	Region          string
	Service         string // e.g. "bedrock", "sagemaker", "execute-api"
	TimeProvider    func() time.Time
}

// SigV4Strategy signs outbound HTTP requests to AWS endpoints using the official AWS SDK v2 Signer.
type SigV4Strategy struct {
	accessKeyID     string
	secretAccessKey string
	sessionToken    string
	region          string
	service         string
	signer          *v4.Signer
	timeProvider    func() time.Time
}

// NewSigV4Strategy creates a new SigV4Strategy.
func NewSigV4Strategy(cfg SigV4Config) (*SigV4Strategy, error) {
	if strings.TrimSpace(cfg.AccessKeyID) == "" {
		return nil, errors.New("sigv4: access_key_id is required")
	}
	if strings.TrimSpace(cfg.SecretAccessKey) == "" {
		return nil, errors.New("sigv4: secret_access_key is required")
	}
	if strings.TrimSpace(cfg.Region) == "" {
		return nil, errors.New("sigv4: region is required")
	}
	if strings.TrimSpace(cfg.Service) == "" {
		return nil, errors.New("sigv4: service is required")
	}

	tp := cfg.TimeProvider
	if tp == nil {
		tp = time.Now
	}

	return &SigV4Strategy{
		accessKeyID:     strings.TrimSpace(cfg.AccessKeyID),
		secretAccessKey: strings.TrimSpace(cfg.SecretAccessKey),
		sessionToken:    strings.TrimSpace(cfg.SessionToken),
		region:          strings.TrimSpace(cfg.Region),
		service:         strings.TrimSpace(cfg.Service),
		signer:          v4.NewSigner(),
		timeProvider:    tp,
	}, nil
}

// Type returns the unique strategy identifier.
func (s *SigV4Strategy) Type() string {
	return "aws_sigv4"
}

// Apply signs the outbound HTTP request using AWS SigV4.
func (s *SigV4Strategy) Apply(ctx context.Context, req *http.Request, authCtx *UpstreamAuthContext) error {
	if req == nil {
		return errors.New("sigv4: nil request")
	}

	var payloadHash string
	if req.Body != nil {
		bodyBytes, err := io.ReadAll(req.Body)
		if err != nil {
			return fmt.Errorf("sigv4: read request body: %w", err)
		}
		// Reset body reader for downstream execution
		req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		req.ContentLength = int64(len(bodyBytes))

		if len(bodyBytes) > 0 {
			h := sha256.Sum256(bodyBytes)
			payloadHash = hex.EncodeToString(h[:])
		} else {
			payloadHash = emptyPayloadHash
		}
	} else {
		payloadHash = emptyPayloadHash
		req.Body = http.NoBody
	}

	creds := aws.Credentials{
		AccessKeyID:     s.accessKeyID,
		SecretAccessKey: s.secretAccessKey,
		SessionToken:    s.sessionToken,
	}

	signTime := s.timeProvider().UTC()

	// Ensure Host header is explicitly populated from URL host if missing
	if req.Host == "" && req.URL != nil {
		req.Host = req.URL.Host
	}

	err := s.signer.SignHTTP(ctx, creds, req, payloadHash, s.service, s.region, signTime)
	if err != nil {
		return fmt.Errorf("sigv4: sign http request: %w", err)
	}

	// For AWS Bedrock / S3 endpoints, X-Amz-Content-Sha256 is expected
	if req.Header.Get("X-Amz-Content-Sha256") == "" {
		req.Header.Set("X-Amz-Content-Sha256", payloadHash)
	}

	return nil
}
