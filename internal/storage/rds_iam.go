package storage

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/security/network"
	"github.com/jackc/pgx/v5"
	"golang.org/x/sync/singleflight"
)

const (
	defaultRDSIAMPort          uint16 = 5432
	defaultRDSIAMTokenTTL             = 15 * time.Minute
	defaultRDSIAMRefreshBefore        = 3 * time.Minute
	defaultSTSVersion                 = "2011-06-15"
	defaultSTSSessionName             = "goroute-rds-iam"
	emptyPayloadSHA256                = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)

// RDSIAMConfig configures AWS RDS IAM Database Authentication (rds-db:connect).
type RDSIAMConfig struct {
	Enabled              bool
	AllowAmbientCloudIAM bool // Default false: must be true to read AWS_* ambient env vars / IRSA files

	Host     string
	Port     uint16
	Region   string
	DBUser   string
	TokenTTL time.Duration // Default 15 minutes (AWS RDS maximum)

	// Static or base IAM credentials (for direct signing or STS AssumeRole)
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string

	// STS AssumeRole / OIDC Web Identity (IRSA)
	RoleARN              string
	RoleSessionName      string
	ExternalID           string
	WebIdentityToken     string
	WebIdentityTokenFile string
	STSEndpoint          string // Optional override; defaults to https://sts.<region>.amazonaws.com

	NetPolicy *network.Policy
	Now       func() time.Time
}

type awsSTSCredentials struct {
	AccessKeyID     string    `xml:"AccessKeyId"`
	SecretAccessKey string    `xml:"SecretAccessKey"`
	SessionToken    string    `xml:"SessionToken"`
	Expiration      time.Time `xml:"Expiration"`
}

type assumeRoleResponseXML struct {
	Credentials awsSTSCredentials `xml:"AssumeRoleResult>Credentials"`
}

type assumeRoleWithWebIdentityResponseXML struct {
	Credentials awsSTSCredentials `xml:"AssumeRoleWithWebIdentityResult>Credentials"`
}

// BuildRDSIAMAuthToken generates an AWS RDS IAM database authentication token
// (SigV4 presigned rds-db:connect URL without the https:// scheme) using static IAM
// credentials, STS AssumeRole, or OIDC Web Identity (IRSA).
func BuildRDSIAMAuthToken(ctx context.Context, cfg RDSIAMConfig) (string, error) {
	resolved, err := normalizeRDSIAMConfig(cfg)
	if err != nil {
		return "", err
	}
	creds, err := resolveRDSIAMCredentials(ctx, resolved)
	if err != nil {
		return "", err
	}
	nowFn := resolved.Now
	if nowFn == nil {
		nowFn = time.Now
	}
	return signRDSIAMToken(resolved.Host, resolved.Port, resolved.Region, resolved.DBUser, creds, resolved.TokenTTL, nowFn().UTC())
}

// RDSIAMTokenProvider caches and periodically refreshes AWS RDS IAM auth tokens
// and STS/IRSA credentials for pgxpool BeforeConnect hooks without restarting the pool.
type RDSIAMTokenProvider struct {
	cfg           RDSIAMConfig
	refreshBefore time.Duration
	now           func() time.Time

	mu           sync.RWMutex
	cachedCreds  *awsSTSCredentials
	cachedToken  string
	tokenExpires time.Time
	sfGroup      singleflight.Group
}

// NewRDSIAMTokenProvider constructs an RDSIAMTokenProvider.
func NewRDSIAMTokenProvider(cfg RDSIAMConfig) (*RDSIAMTokenProvider, error) {
	normalized, err := normalizeRDSIAMConfig(cfg)
	if err != nil {
		return nil, err
	}
	nowFn := normalized.Now
	if nowFn == nil {
		nowFn = time.Now
	}
	refreshBefore := defaultRDSIAMRefreshBefore
	if normalized.TokenTTL <= refreshBefore*3/2 {
		refreshBefore = normalized.TokenTTL / 4
	}
	return &RDSIAMTokenProvider{
		cfg:           normalized,
		refreshBefore: refreshBefore,
		now:           nowFn,
	}, nil
}

// Token returns a valid RDS IAM auth token, refreshing proactively before expiry.
func (p *RDSIAMTokenProvider) Token(ctx context.Context) (string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}

	now := p.now().UTC()
	p.mu.RLock()
	if p.cachedToken != "" && now.Add(p.refreshBefore).Before(p.tokenExpires) {
		tok := p.cachedToken
		p.mu.RUnlock()
		return tok, nil
	}
	p.mu.RUnlock()

	ch := p.sfGroup.DoChan("rds-iam-token", func() (any, error) {
		refreshCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
		defer cancel()
		return p.refreshToken(refreshCtx)
	})

	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case res := <-ch:
		if res.Err != nil {
			return "", res.Err
		}
		tok, _ := res.Val.(string)
		return tok, nil
	}
}

// BeforeConnect injects a fresh RDS IAM auth token into pgx.ConnConfig before a new
// PostgreSQL connection is dialed, enabling seamless credential rotation without pool restarts.
func (p *RDSIAMTokenProvider) BeforeConnect(ctx context.Context, connCfg *pgx.ConnConfig) error {
	if connCfg == nil {
		return errors.New("rds_iam: nil pgx.ConnConfig")
	}
	token, err := p.Token(ctx)
	if err != nil {
		return err
	}
	connCfg.Password = token
	if p.cfg.DBUser != "" {
		connCfg.User = p.cfg.DBUser
	}
	return nil
}

func (p *RDSIAMTokenProvider) refreshToken(ctx context.Context) (string, error) {
	now := p.now().UTC()
	p.mu.RLock()
	if p.cachedToken != "" && now.Add(p.refreshBefore).Before(p.tokenExpires) {
		tok := p.cachedToken
		p.mu.RUnlock()
		return tok, nil
	}
	creds := p.cachedCreds
	p.mu.RUnlock()

	// Reuse cached STS credentials if still valid with a 60s buffer.
	if creds == nil || (!creds.Expiration.IsZero() && now.Add(60*time.Second).After(creds.Expiration)) {
		resolvedCreds, err := resolveRDSIAMCredentials(ctx, p.cfg)
		if err != nil {
			return "", err
		}
		creds = &resolvedCreds
	}

	signTime := p.now().UTC()
	tok, err := signRDSIAMToken(p.cfg.Host, p.cfg.Port, p.cfg.Region, p.cfg.DBUser, *creds, p.cfg.TokenTTL, signTime)
	if err != nil {
		return "", err
	}

	p.mu.Lock()
	p.cachedCreds = creds
	p.cachedToken = tok
	p.tokenExpires = signTime.Add(p.cfg.TokenTTL)
	p.mu.Unlock()

	return tok, nil
}

func normalizeRDSIAMConfig(cfg RDSIAMConfig) (RDSIAMConfig, error) {
	out := cfg
	if out.AllowAmbientCloudIAM {
		if out.Region == "" {
			out.Region = strings.TrimSpace(os.Getenv("AWS_REGION"))
			if out.Region == "" {
				out.Region = strings.TrimSpace(os.Getenv("AWS_DEFAULT_REGION"))
			}
		}
		if out.AccessKeyID == "" {
			out.AccessKeyID = strings.TrimSpace(os.Getenv("AWS_ACCESS_KEY_ID"))
		}
		if out.SecretAccessKey == "" {
			out.SecretAccessKey = strings.TrimSpace(os.Getenv("AWS_SECRET_ACCESS_KEY"))
		}
		if out.SessionToken == "" {
			out.SessionToken = strings.TrimSpace(os.Getenv("AWS_SESSION_TOKEN"))
		}
		if out.RoleARN == "" {
			out.RoleARN = strings.TrimSpace(os.Getenv("AWS_ROLE_ARN"))
		}
		if out.WebIdentityTokenFile == "" {
			out.WebIdentityTokenFile = strings.TrimSpace(os.Getenv("AWS_WEB_IDENTITY_TOKEN_FILE"))
		}
		if out.RoleSessionName == "" {
			out.RoleSessionName = strings.TrimSpace(os.Getenv("AWS_ROLE_SESSION_NAME"))
		}
	}

	out.Host = strings.TrimSpace(out.Host)
	out.Region = strings.TrimSpace(out.Region)
	out.DBUser = strings.TrimSpace(out.DBUser)
	if out.Host == "" {
		return RDSIAMConfig{}, errors.New("rds_iam: host is required")
	}
	if out.Region == "" {
		return RDSIAMConfig{}, errors.New("rds_iam: region is required")
	}
	if out.DBUser == "" {
		return RDSIAMConfig{}, errors.New("rds_iam: db_user is required")
	}
	if out.Port == 0 {
		out.Port = defaultRDSIAMPort
	}
	if out.TokenTTL <= 0 {
		out.TokenTTL = defaultRDSIAMTokenTTL
	}
	if out.RoleSessionName == "" {
		out.RoleSessionName = defaultSTSSessionName
	}
	if out.STSEndpoint == "" {
		out.STSEndpoint = fmt.Sprintf("https://sts.%s.amazonaws.com/", out.Region)
	}
	return out, nil
}

func resolveRDSIAMCredentials(ctx context.Context, cfg RDSIAMConfig) (awsSTSCredentials, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	// 1. OIDC Web Identity (IRSA): RoleARN + (WebIdentityToken or WebIdentityTokenFile)
	if cfg.RoleARN != "" && (cfg.WebIdentityToken != "" || cfg.WebIdentityTokenFile != "") {
		token := strings.TrimSpace(cfg.WebIdentityToken)
		if token == "" {
			raw, err := os.ReadFile(cfg.WebIdentityTokenFile)
			if err != nil {
				return awsSTSCredentials{}, fmt.Errorf("rds_iam: read web identity token file: %w", err)
			}
			token = strings.TrimSpace(string(raw))
		}
		if token == "" {
			return awsSTSCredentials{}, errors.New("rds_iam: empty web identity token")
		}
		return callSTSAssumeRoleWithWebIdentity(ctx, cfg, token)
	}

	// 2. Static IAM credentials + optional STS AssumeRole
	if cfg.AccessKeyID != "" && cfg.SecretAccessKey != "" {
		baseCreds := awsSTSCredentials{
			AccessKeyID:     cfg.AccessKeyID,
			SecretAccessKey: cfg.SecretAccessKey,
			SessionToken:    cfg.SessionToken,
		}
		if cfg.RoleARN != "" {
			return callSTSAssumeRole(ctx, cfg, baseCreds)
		}
		return baseCreds, nil
	}

	return awsSTSCredentials{}, errors.New("rds_iam: no IAM credentials configured (provide static credentials, STS AssumeRole, or IRSA web identity)")
}

func callSTSAssumeRoleWithWebIdentity(ctx context.Context, cfg RDSIAMConfig, webIdentityToken string) (awsSTSCredentials, error) {
	form := url.Values{}
	form.Set("Action", "AssumeRoleWithWebIdentity")
	form.Set("Version", defaultSTSVersion)
	form.Set("RoleArn", cfg.RoleARN)
	form.Set("RoleSessionName", cfg.RoleSessionName)
	form.Set("WebIdentityToken", webIdentityToken)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.STSEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return awsSTSCredentials{}, fmt.Errorf("rds_iam: create sts web identity request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := network.NewHTTPClient(cfg.NetPolicy)
	resp, err := client.Do(req)
	if err != nil {
		return awsSTSCredentials{}, fmt.Errorf("rds_iam: sts web identity request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	if err != nil {
		return awsSTSCredentials{}, fmt.Errorf("rds_iam: read sts response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return awsSTSCredentials{}, fmt.Errorf("rds_iam: sts AssumeRoleWithWebIdentity HTTP %d: %s", resp.StatusCode, string(body))
	}

	var parsed assumeRoleWithWebIdentityResponseXML
	if err := xml.Unmarshal(body, &parsed); err != nil {
		return awsSTSCredentials{}, fmt.Errorf("rds_iam: parse sts web identity xml: %w", err)
	}
	if parsed.Credentials.AccessKeyID == "" || parsed.Credentials.SecretAccessKey == "" {
		return awsSTSCredentials{}, errors.New("rds_iam: sts AssumeRoleWithWebIdentity returned empty credentials")
	}
	return parsed.Credentials, nil
}

func callSTSAssumeRole(ctx context.Context, cfg RDSIAMConfig, base awsSTSCredentials) (awsSTSCredentials, error) {
	form := url.Values{}
	form.Set("Action", "AssumeRole")
	form.Set("Version", defaultSTSVersion)
	form.Set("RoleArn", cfg.RoleARN)
	form.Set("RoleSessionName", cfg.RoleSessionName)
	if cfg.ExternalID != "" {
		form.Set("ExternalId", cfg.ExternalID)
	}
	payload := []byte(form.Encode())

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.STSEndpoint, strings.NewReader(string(payload)))
	if err != nil {
		return awsSTSCredentials{}, fmt.Errorf("rds_iam: create sts assume role request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	nowFn := cfg.Now
	if nowFn == nil {
		nowFn = time.Now
	}
	signSTSRequestSigV4(req, payload, cfg.Region, base, nowFn().UTC())

	client := network.NewHTTPClient(cfg.NetPolicy)
	resp, err := client.Do(req)
	if err != nil {
		return awsSTSCredentials{}, fmt.Errorf("rds_iam: sts assume role request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	if err != nil {
		return awsSTSCredentials{}, fmt.Errorf("rds_iam: read sts response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return awsSTSCredentials{}, fmt.Errorf("rds_iam: sts AssumeRole HTTP %d: %s", resp.StatusCode, string(body))
	}

	var parsed assumeRoleResponseXML
	if err := xml.Unmarshal(body, &parsed); err != nil {
		return awsSTSCredentials{}, fmt.Errorf("rds_iam: parse sts assume role xml: %w", err)
	}
	if parsed.Credentials.AccessKeyID == "" || parsed.Credentials.SecretAccessKey == "" {
		return awsSTSCredentials{}, errors.New("rds_iam: sts AssumeRole returned empty credentials")
	}
	return parsed.Credentials, nil
}

func signRDSIAMToken(host string, port uint16, region, dbUser string, creds awsSTSCredentials, ttl time.Duration, signTime time.Time) (string, error) {
	if creds.AccessKeyID == "" || creds.SecretAccessKey == "" {
		return "", errors.New("rds_iam: access key id and secret access key are required")
	}
	hostPort := fmt.Sprintf("%s:%d", host, port)
	amzDate := signTime.UTC().Format("20060102T150405Z")
	dateStamp := signTime.UTC().Format("20060102")
	credentialScope := fmt.Sprintf("%s/%s/rds-db/aws4_request", dateStamp, region)

	expiresSec := int64(ttl / time.Second)
	if expiresSec <= 0 {
		expiresSec = 900
	}

	params := [][2]string{
		{"Action", "connect"},
		{"DBUser", dbUser},
		{"X-Amz-Algorithm", "AWS4-HMAC-SHA256"},
		{"X-Amz-Credential", creds.AccessKeyID + "/" + credentialScope},
		{"X-Amz-Date", amzDate},
		{"X-Amz-Expires", strconv.FormatInt(expiresSec, 10)},
		{"X-Amz-SignedHeaders", "host"},
	}
	if creds.SessionToken != "" {
		params = append(params, [2]string{"X-Amz-Security-Token", creds.SessionToken})
	}
	sort.Slice(params, func(i, j int) bool {
		return params[i][0] < params[j][0]
	})

	var qParts []string
	for _, kv := range params {
		qParts = append(qParts, awsURIEncode(kv[0])+"="+awsURIEncode(kv[1]))
	}
	canonicalQuery := strings.Join(qParts, "&")

	canonicalHeaders := fmt.Sprintf("host:%s\n", hostPort)
	canonicalRequest := fmt.Sprintf("GET\n/\n%s\n%s\nhost\n%s",
		canonicalQuery,
		canonicalHeaders,
		emptyPayloadSHA256,
	)

	reqSum := sha256.Sum256([]byte(canonicalRequest))
	stringToSign := fmt.Sprintf("AWS4-HMAC-SHA256\n%s\n%s\n%s",
		amzDate,
		credentialScope,
		hex.EncodeToString(reqSum[:]),
	)

	kSigning := deriveSigV4Key(creds.SecretAccessKey, dateStamp, region, "rds-db")
	sig := hex.EncodeToString(hmacSHA256Bytes(kSigning, stringToSign))

	return hostPort + "/?" + canonicalQuery + "&X-Amz-Signature=" + sig, nil
}

func signSTSRequestSigV4(req *http.Request, payload []byte, region string, creds awsSTSCredentials, signTime time.Time) {
	amzDate := signTime.UTC().Format("20060102T150405Z")
	dateStamp := signTime.UTC().Format("20060102")

	host := req.Host
	if host == "" && req.URL != nil {
		host = req.URL.Host
	}

	payloadSum := sha256.Sum256(payload)
	payloadHash := hex.EncodeToString(payloadSum[:])

	req.Header.Set("Host", host)
	req.Header.Set("X-Amz-Date", amzDate)
	if creds.SessionToken != "" {
		req.Header.Set("X-Amz-Security-Token", creds.SessionToken)
	}

	headers := map[string]string{
		"content-type": req.Header.Get("Content-Type"),
		"host":         host,
		"x-amz-date":   amzDate,
	}
	if creds.SessionToken != "" {
		headers["x-amz-security-token"] = creds.SessionToken
	}

	var keys []string
	for k := range headers {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var canonHeaders strings.Builder
	for _, k := range keys {
		canonHeaders.WriteString(k)
		canonHeaders.WriteByte(':')
		canonHeaders.WriteString(strings.TrimSpace(headers[k]))
		canonHeaders.WriteByte('\n')
	}
	signedHeaders := strings.Join(keys, ";")

	canonURI := req.URL.EscapedPath()
	if canonURI == "" {
		canonURI = "/"
	}
	canonRequest := fmt.Sprintf("%s\n%s\n%s\n%s\n%s\n%s",
		req.Method,
		canonURI,
		req.URL.RawQuery,
		canonHeaders.String(),
		signedHeaders,
		payloadHash,
	)

	reqSum := sha256.Sum256([]byte(canonRequest))
	scope := fmt.Sprintf("%s/%s/sts/aws4_request", dateStamp, region)
	stringToSign := fmt.Sprintf("AWS4-HMAC-SHA256\n%s\n%s\n%s",
		amzDate,
		scope,
		hex.EncodeToString(reqSum[:]),
	)

	kSigning := deriveSigV4Key(creds.SecretAccessKey, dateStamp, region, "sts")
	sig := hex.EncodeToString(hmacSHA256Bytes(kSigning, stringToSign))

	auth := fmt.Sprintf("AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		creds.AccessKeyID,
		scope,
		signedHeaders,
		sig,
	)
	req.Header.Set("Authorization", auth)
}

func deriveSigV4Key(secret, dateStamp, region, service string) []byte {
	kDate := hmacSHA256Bytes([]byte("AWS4"+secret), dateStamp)
	kRegion := hmacSHA256Bytes(kDate, region)
	kService := hmacSHA256Bytes(kRegion, service)
	return hmacSHA256Bytes(kService, "aws4_request")
}

func hmacSHA256Bytes(key []byte, data string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(data))
	return m.Sum(nil)
}

// awsURIEncode implements RFC 3986 percent-encoding required by AWS SigV4.
func awsURIEncode(s string) string {
	escaped := url.QueryEscape(s)
	escaped = strings.ReplaceAll(escaped, "+", "%20")
	escaped = strings.ReplaceAll(escaped, "*", "%2A")
	escaped = strings.ReplaceAll(escaped, "%7E", "~")
	return escaped
}
