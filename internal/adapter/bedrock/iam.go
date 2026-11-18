package bedrock

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/security/network"
	"golang.org/x/sync/singleflight"
)

const (
	defaultIMDSEndpoint       = "http://169.254.169.254"
	defaultECSEndpoint        = "http://169.254.170.2"
	defaultBedrockRegion      = "us-east-1"
	defaultBedrockRoleSession = "goroute-bedrock"
	defaultIMDSTokenTTLHeader = "21600"
	defaultCredRefreshSkew    = 5 * time.Minute
)

// ErrAmbientIAMDisabled is returned when ambient cloud IAM resolution is attempted
// while AllowAmbientCloudIAM is false (the secure default).
var ErrAmbientIAMDisabled = errors.New("bedrock: ambient cloud IAM is disabled (allow_ambient_cloud_iam=false)")

// AmbientIAMConfig configures opt-in AWS ambient IAM resolution (Env / IRSA / ECS / IMDSv2).
type AmbientIAMConfig struct {
	AllowAmbientCloudIAM bool
	Region               string
	IMDSEndpoint         string
	ECSEndpoint          string
	STSEndpoint          string
	WebIdentityTokenFile string
	RoleARN              string
	RoleSessionName      string
	SSRFPolicy           *network.Policy
	Now                  func() time.Time
}

// AmbientCredentialProvider resolves and caches temporary AWS credentials from
// ambient runtime sources (env, IRSA, ECS, IMDSv2) only when AllowAmbientCloudIAM is true.
type AmbientCredentialProvider struct {
	cfg AmbientIAMConfig
	now func() time.Time

	mu        sync.RWMutex
	cached    *Credentials
	expiresAt time.Time
	sfGroup   singleflight.Group
}

// NewAmbientCredentialProvider constructs an AmbientCredentialProvider.
func NewAmbientCredentialProvider(cfg AmbientIAMConfig) *AmbientCredentialProvider {
	nowFn := cfg.Now
	if nowFn == nil {
		nowFn = time.Now
	}
	return &AmbientCredentialProvider{
		cfg: cfg,
		now: nowFn,
	}
}

// GetCredentials resolves AWS credentials from the ambient runtime chain if opted in.
func (p *AmbientCredentialProvider) GetCredentials(ctx context.Context) (*Credentials, error) {
	if !p.cfg.AllowAmbientCloudIAM {
		return nil, ErrAmbientIAMDisabled
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	now := p.now().UTC()
	p.mu.RLock()
	if p.cached != nil && (p.expiresAt.IsZero() || now.Before(p.expiresAt)) {
		cp := *p.cached
		p.mu.RUnlock()
		return &cp, nil
	}
	p.mu.RUnlock()

	ch := p.sfGroup.DoChan("bedrock-ambient-creds", func() (any, error) {
		refreshCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()
		return p.refresh(refreshCtx)
	})

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case res := <-ch:
		if res.Err != nil {
			return nil, res.Err
		}
		c, _ := res.Val.(*Credentials)
		if c == nil {
			return nil, errors.New("bedrock: ambient credential resolution returned nil")
		}
		cp := *c
		return &cp, nil
	}
}

func (p *AmbientCredentialProvider) refresh(ctx context.Context) (*Credentials, error) {
	now := p.now().UTC()
	p.mu.RLock()
	if p.cached != nil && (p.expiresAt.IsZero() || now.Before(p.expiresAt)) {
		cp := *p.cached
		p.mu.RUnlock()
		return &cp, nil
	}
	p.mu.RUnlock()

	creds, exp, err := p.resolveFromRuntime(ctx)
	if err != nil {
		return nil, err
	}

	var refreshAt time.Time
	if !exp.IsZero() {
		ttl := exp.Sub(now)
		skew := defaultCredRefreshSkew
		if ttl <= skew*3/2 {
			skew = ttl / 4
		}
		refreshAt = exp.Add(-skew)
	}

	p.mu.Lock()
	p.cached = creds
	p.expiresAt = refreshAt
	p.mu.Unlock()

	cp := *creds
	return &cp, nil
}

func (p *AmbientCredentialProvider) resolveRegion() string {
	if r := strings.TrimSpace(p.cfg.Region); r != "" {
		return r
	}
	if r := strings.TrimSpace(os.Getenv("AWS_REGION")); r != "" {
		return r
	}
	if r := strings.TrimSpace(os.Getenv("AWS_DEFAULT_REGION")); r != "" {
		return r
	}
	return defaultBedrockRegion
}

func (p *AmbientCredentialProvider) resolveFromRuntime(ctx context.Context) (*Credentials, time.Time, error) {
	region := p.resolveRegion()

	// 1. Static environment credentials
	if ak := strings.TrimSpace(os.Getenv("AWS_ACCESS_KEY_ID")); ak != "" {
		if sk := strings.TrimSpace(os.Getenv("AWS_SECRET_ACCESS_KEY")); sk != "" {
			return &Credentials{
				AccessKeyID:     ak,
				SecretAccessKey: sk,
				SessionToken:    strings.TrimSpace(os.Getenv("AWS_SESSION_TOKEN")),
				Region:          region,
			}, time.Time{}, nil
		}
	}

	// 2. IRSA (OIDC Web Identity via STS AssumeRoleWithWebIdentity)
	tokenFile := strings.TrimSpace(p.cfg.WebIdentityTokenFile)
	if tokenFile == "" {
		tokenFile = strings.TrimSpace(os.Getenv("AWS_WEB_IDENTITY_TOKEN_FILE"))
	}
	roleARN := strings.TrimSpace(p.cfg.RoleARN)
	if roleARN == "" {
		roleARN = strings.TrimSpace(os.Getenv("AWS_ROLE_ARN"))
	}
	if tokenFile != "" && roleARN != "" {
		return p.resolveIRSA(ctx, region, roleARN, tokenFile)
	}

	// Construct metadata HTTP client strictly through network.NewAmbientIAMHTTPClient
	metaClient, err := network.NewAmbientIAMHTTPClient(p.cfg.SSRFPolicy, p.cfg.AllowAmbientCloudIAM)
	if err != nil {
		return nil, time.Time{}, err
	}

	// 3. ECS Container Credentials
	if relURI := strings.TrimSpace(os.Getenv("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI")); relURI != "" {
		base := strings.TrimRight(p.cfg.ECSEndpoint, "/")
		if base == "" {
			base = defaultECSEndpoint
		}
		if !strings.HasPrefix(relURI, "/") {
			relURI = "/" + relURI
		}
		return p.resolveECS(ctx, metaClient, base+relURI, region)
	}
	if fullURI := strings.TrimSpace(os.Getenv("AWS_CONTAINER_CREDENTIALS_FULL_URI")); fullURI != "" {
		return p.resolveECS(ctx, metaClient, fullURI, region)
	}

	// 4. EC2 IMDSv2
	return p.resolveIMDSv2(ctx, metaClient, region)
}

type stsAssumeRoleWebIdentityResp struct {
	AccessKeyID     string    `xml:"AssumeRoleWithWebIdentityResult>Credentials>AccessKeyId"`
	SecretAccessKey string    `xml:"AssumeRoleWithWebIdentityResult>Credentials>SecretAccessKey"`
	SessionToken    string    `xml:"AssumeRoleWithWebIdentityResult>Credentials>SessionToken"`
	Expiration      time.Time `xml:"AssumeRoleWithWebIdentityResult>Credentials>Expiration"`
}

func (p *AmbientCredentialProvider) resolveIRSA(ctx context.Context, region, roleARN, tokenFile string) (*Credentials, time.Time, error) {
	rawTok, err := os.ReadFile(tokenFile)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("bedrock irsa: read web identity token file: %w", err)
	}
	jwtTok := strings.TrimSpace(string(rawTok))
	if jwtTok == "" {
		return nil, time.Time{}, errors.New("bedrock irsa: web identity token file is empty")
	}

	sessionName := strings.TrimSpace(p.cfg.RoleSessionName)
	if sessionName == "" {
		sessionName = strings.TrimSpace(os.Getenv("AWS_ROLE_SESSION_NAME"))
	}
	if sessionName == "" {
		sessionName = defaultBedrockRoleSession
	}

	stsEndpoint := strings.TrimSpace(p.cfg.STSEndpoint)
	if stsEndpoint == "" {
		stsEndpoint = fmt.Sprintf("https://sts.%s.amazonaws.com/", region)
	}

	form := url.Values{}
	form.Set("Action", "AssumeRoleWithWebIdentity")
	form.Set("Version", "2011-06-15")
	form.Set("RoleArn", roleARN)
	form.Set("RoleSessionName", sessionName)
	form.Set("WebIdentityToken", jwtTok)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, stsEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("bedrock irsa: create sts request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := network.NewHTTPClient(p.cfg.SSRFPolicy)
	resp, err := client.Do(req)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("bedrock irsa: sts request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("bedrock irsa: read sts response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, time.Time{}, fmt.Errorf("bedrock irsa: sts HTTP %d: %s", resp.StatusCode, string(body))
	}

	var parsed stsAssumeRoleWebIdentityResp
	if err := xml.Unmarshal(body, &parsed); err != nil {
		return nil, time.Time{}, fmt.Errorf("bedrock irsa: parse sts xml: %w", err)
	}
	if parsed.AccessKeyID == "" || parsed.SecretAccessKey == "" {
		return nil, time.Time{}, errors.New("bedrock irsa: sts returned empty credentials")
	}
	return &Credentials{
		AccessKeyID:     parsed.AccessKeyID,
		SecretAccessKey: parsed.SecretAccessKey,
		SessionToken:    parsed.SessionToken,
		Region:          region,
	}, parsed.Expiration, nil
}

type awsMetadataCredsJSON struct {
	Code            string `json:"Code"`
	AccessKeyID     string `json:"AccessKeyId"`
	SecretAccessKey string `json:"SecretAccessKey"`
	Token           string `json:"Token"`
	Expiration      string `json:"Expiration"`
}

func (p *AmbientCredentialProvider) resolveECS(ctx context.Context, client *http.Client, endpoint, region string) (*Credentials, time.Time, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("bedrock ecs: create request: %w", err)
	}
	if authTok := strings.TrimSpace(os.Getenv("AWS_CONTAINER_AUTHORIZATION_TOKEN")); authTok != "" {
		req.Header.Set("Authorization", authTok)
	} else if authFile := strings.TrimSpace(os.Getenv("AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE")); authFile != "" {
		if b, readErr := os.ReadFile(authFile); readErr == nil && len(b) > 0 {
			req.Header.Set("Authorization", strings.TrimSpace(string(b)))
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("bedrock ecs: request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 128*1024))
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("bedrock ecs: read response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, time.Time{}, fmt.Errorf("bedrock ecs: HTTP %d: %s", resp.StatusCode, string(body))
	}

	var parsed awsMetadataCredsJSON
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, time.Time{}, fmt.Errorf("bedrock ecs: decode json: %w", err)
	}
	if parsed.AccessKeyID == "" || parsed.SecretAccessKey == "" {
		return nil, time.Time{}, errors.New("bedrock ecs: empty credentials in response")
	}

	exp, _ := time.Parse(time.RFC3339, parsed.Expiration)
	return &Credentials{
		AccessKeyID:     parsed.AccessKeyID,
		SecretAccessKey: parsed.SecretAccessKey,
		SessionToken:    parsed.Token,
		Region:          region,
	}, exp, nil
}

func (p *AmbientCredentialProvider) resolveIMDSv2(ctx context.Context, client *http.Client, region string) (*Credentials, time.Time, error) {
	base := strings.TrimRight(p.cfg.IMDSEndpoint, "/")
	if base == "" {
		base = defaultIMDSEndpoint
	}

	// Step 1: Acquire IMDSv2 session token via PUT.
	tokenReq, err := http.NewRequestWithContext(ctx, http.MethodPut, base+"/latest/api/token", nil)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("bedrock imdsv2: create token request: %w", err)
	}
	tokenReq.Header.Set("X-aws-ec2-metadata-token-ttl-seconds", defaultIMDSTokenTTLHeader)

	tokenResp, err := client.Do(tokenReq)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("bedrock imdsv2: token request failed: %w", err)
	}
	tokenBytes, err := io.ReadAll(io.LimitReader(tokenResp.Body, 8192))
	tokenResp.Body.Close()
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("bedrock imdsv2: read token: %w", err)
	}
	if tokenResp.StatusCode < 200 || tokenResp.StatusCode >= 300 {
		return nil, time.Time{}, fmt.Errorf("bedrock imdsv2: token HTTP %d: %s", tokenResp.StatusCode, string(tokenBytes))
	}
	imdsToken := strings.TrimSpace(string(tokenBytes))
	if imdsToken == "" {
		return nil, time.Time{}, errors.New("bedrock imdsv2: empty session token")
	}

	// Step 2: List IAM role name.
	roleReq, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/latest/meta-data/iam/security-credentials/", nil)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("bedrock imdsv2: create role request: %w", err)
	}
	roleReq.Header.Set("X-aws-ec2-metadata-token", imdsToken)

	roleResp, err := client.Do(roleReq)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("bedrock imdsv2: role list failed: %w", err)
	}
	roleBytes, err := io.ReadAll(io.LimitReader(roleResp.Body, 8192))
	roleResp.Body.Close()
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("bedrock imdsv2: read role name: %w", err)
	}
	if roleResp.StatusCode < 200 || roleResp.StatusCode >= 300 {
		return nil, time.Time{}, fmt.Errorf("bedrock imdsv2: role list HTTP %d", roleResp.StatusCode)
	}
	var roleName string
	for _, line := range strings.Split(string(roleBytes), "\n") {
		if trimmed := strings.TrimSpace(line); trimmed != "" {
			roleName = trimmed
			break
		}
	}
	if roleName == "" {
		return nil, time.Time{}, errors.New("bedrock imdsv2: no IAM role attached to instance")
	}

	// Step 3: Fetch temporary credentials for the role.
	credReq, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/latest/meta-data/iam/security-credentials/"+url.PathEscape(roleName), nil)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("bedrock imdsv2: create credentials request: %w", err)
	}
	credReq.Header.Set("X-aws-ec2-metadata-token", imdsToken)

	credResp, err := client.Do(credReq)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("bedrock imdsv2: credentials fetch failed: %w", err)
	}
	credBytes, err := io.ReadAll(io.LimitReader(credResp.Body, 64*1024))
	credResp.Body.Close()
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("bedrock imdsv2: read credentials: %w", err)
	}
	if credResp.StatusCode < 200 || credResp.StatusCode >= 300 {
		return nil, time.Time{}, fmt.Errorf("bedrock imdsv2: credentials HTTP %d: %s", credResp.StatusCode, string(credBytes))
	}

	var parsed awsMetadataCredsJSON
	if err := json.Unmarshal(credBytes, &parsed); err != nil {
		return nil, time.Time{}, fmt.Errorf("bedrock imdsv2: decode credentials json: %w", err)
	}
	if parsed.AccessKeyID == "" || parsed.SecretAccessKey == "" {
		return nil, time.Time{}, errors.New("bedrock imdsv2: empty credentials in response")
	}

	exp, _ := time.Parse(time.RFC3339, parsed.Expiration)
	return &Credentials{
		AccessKeyID:     parsed.AccessKeyID,
		SecretAccessKey: parsed.SecretAccessKey,
		SessionToken:    parsed.Token,
		Region:          region,
	}, exp, nil
}

func (a *Adapter) resolveCredentials(ctx context.Context, cred *domain.ProviderCredential) (*Credentials, error) {
	if cred != nil {
		raw := strings.TrimSpace(cred.DecryptedAPIKey)
		authMode := ""
		if cred.Headers != nil {
			authMode = strings.ToLower(strings.TrimSpace(cred.Headers["auth_mode"]))
		}
		isAmbientSentinel := raw == "" || strings.EqualFold(raw, "ambient") || strings.EqualFold(raw, "iam") || authMode == "ambient_iam"
		if !isAmbientSentinel {
			return parseCredentials(cred)
		}
	}

	a.ambientMu.RLock()
	allowed := a.allowAmbientCloudIAM
	provider := a.ambientProvider
	a.ambientMu.RUnlock()

	if !allowed {
		if cred == nil {
			return nil, &domain.GatewayError{
				StatusCode:  http.StatusUnauthorized,
				Type:        domain.ErrorTypeAuthentication,
				Code:        "missing_credential",
				Message:     "bedrock credentials missing",
				AuthFailure: true,
			}
		}
		return nil, &domain.GatewayError{
			StatusCode:  http.StatusUnauthorized,
			Type:        domain.ErrorTypeAuthentication,
			Code:        "invalid_aws_credential",
			Message:     ErrAmbientIAMDisabled.Error(),
			AuthFailure: true,
		}
	}

	if provider == nil {
		a.ambientMu.Lock()
		if a.ambientProvider == nil {
			cfg := a.ambientIAMCfg
			cfg.AllowAmbientCloudIAM = true
			if cfg.SSRFPolicy == nil {
				cfg.SSRFPolicy = a.ssrfPolicy
			}
			a.ambientProvider = NewAmbientCredentialProvider(cfg)
		}
		provider = a.ambientProvider
		a.ambientMu.Unlock()
	}

	creds, err := provider.GetCredentials(ctx)
	if err != nil {
		return nil, &domain.GatewayError{
			StatusCode:  http.StatusUnauthorized,
			Type:        domain.ErrorTypeAuthentication,
			Code:        "invalid_aws_credential",
			Message:     err.Error(),
			AuthFailure: true,
		}
	}
	if cred != nil && cred.Headers != nil {
		if r := strings.TrimSpace(cred.Headers["aws_region"]); r != "" {
			creds.Region = r
		}
	}
	return creds, nil
}
