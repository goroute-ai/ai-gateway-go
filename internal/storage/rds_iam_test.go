package storage

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/security/network"
	"github.com/jackc/pgx/v5"
)

func TestBuildRDSIAMAuthToken_MatchesOfficialSigV4Presign(t *testing.T) {
	fixedTime := time.Date(2026, 11, 18, 9, 30, 0, 0, time.UTC)
	cfg := RDSIAMConfig{
		Host:            "prod-db.cluster-abc123.us-east-1.rds.amazonaws.com",
		Port:            5432,
		Region:          "us-east-1",
		DBUser:          "gateway_iam_user",
		AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
		SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		SessionToken:    "IQoJb3JpZ2luX2VjECoaCXVzLWVhc3QtMSJG",
		TokenTTL:        15 * time.Minute,
		Now:             func() time.Time { return fixedTime },
	}

	got, err := BuildRDSIAMAuthToken(context.Background(), cfg)
	if err != nil {
		t.Fatalf("BuildRDSIAMAuthToken failed: %v", err)
	}
	if strings.HasPrefix(got, "https://") || strings.HasPrefix(got, "http://") {
		t.Fatalf("RDS IAM token must not contain URL scheme, got %q", got)
	}

	// Cross-verify byte-for-byte against aws-sdk-go-v2 v4.Signer.PresignHTTP.
	req, err := http.NewRequest(http.MethodGet, "https://"+cfg.Host+":5432/?Action=connect&DBUser="+url.QueryEscape(cfg.DBUser)+"&X-Amz-Expires=900", nil)
	if err != nil {
		t.Fatalf("build reference request: %v", err)
	}
	q := req.URL.Query()
	q.Set("X-Amz-Security-Token", cfg.SessionToken)
	req.URL.RawQuery = q.Encode()

	signer := v4.NewSigner()
	signedURI, _, err := signer.PresignHTTP(
		context.Background(),
		aws.Credentials{
			AccessKeyID:     cfg.AccessKeyID,
			SecretAccessKey: cfg.SecretAccessKey,
			SessionToken:    cfg.SessionToken,
		},
		req,
		emptyPayloadSHA256,
		"rds-db",
		cfg.Region,
		fixedTime,
	)
	if err != nil {
		t.Fatalf("v4 PresignHTTP failed: %v", err)
	}
	expected := strings.TrimPrefix(signedURI, "https://")

	gotURL, err := url.Parse("https://" + got)
	if err != nil {
		t.Fatalf("parse got token URL: %v", err)
	}
	expURL, err := url.Parse("https://" + expected)
	if err != nil {
		t.Fatalf("parse expected token URL: %v", err)
	}

	if gotURL.Host != expURL.Host {
		t.Fatalf("host mismatch: got %q, want %q", gotURL.Host, expURL.Host)
	}
	if gotURL.Query().Get("X-Amz-Signature") != expURL.Query().Get("X-Amz-Signature") {
		t.Fatalf("signature mismatch:\n got: %s\nwant: %s",
			gotURL.Query().Get("X-Amz-Signature"), expURL.Query().Get("X-Amz-Signature"))
	}
	if gotURL.Query().Get("Action") != "connect" || gotURL.Query().Get("DBUser") != cfg.DBUser {
		t.Fatalf("unexpected query params: %v", gotURL.Query())
	}
}

func TestBuildRDSIAMAuthToken_STSAssumeRole(t *testing.T) {
	fixedTime := time.Date(2026, 11, 18, 9, 30, 0, 0, time.UTC)

	var seenAuthHeader string
	var seenAction, seenRoleARN, seenExternalID string

	stsSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenAuthHeader = r.Header.Get("Authorization")
		_ = r.ParseForm()
		seenAction = r.Form.Get("Action")
		seenRoleARN = r.Form.Get("RoleArn")
		seenExternalID = r.Form.Get("ExternalId")

		w.Header().Set("Content-Type", "text/xml")
		_, _ = w.Write([]byte(`
<AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <AssumeRoleResult>
    <Credentials>
      <AccessKeyId>ASIATEMPKEY123</AccessKeyId>
      <SecretAccessKey>tempSecretKey456</SecretAccessKey>
      <SessionToken>tempSessionToken789</SessionToken>
      <Expiration>2026-11-18T10:30:00Z</Expiration>
    </Credentials>
  </AssumeRoleResult>
</AssumeRoleResponse>`))
	}))
	defer stsSrv.Close()

	netPol, err := network.NewPolicy(config.OutboundSSRFConfig{
		AllowPrivateNetworks: true,
		AllowInsecureHTTP:    true,
	})
	if err != nil {
		t.Fatalf("new policy: %v", err)
	}

	tok, err := BuildRDSIAMAuthToken(context.Background(), RDSIAMConfig{
		Host:            "rds.example.internal",
		Port:            5432,
		Region:          "us-west-2",
		DBUser:          "iam_pg_user",
		AccessKeyID:     "AKIA_BASE",
		SecretAccessKey: "SECRET_BASE",
		RoleARN:         "arn:aws:iam::123456789012:role/rds-connect",
		ExternalID:      "ext-123",
		STSEndpoint:     stsSrv.URL,
		NetPolicy:       netPol,
		Now:             func() time.Time { return fixedTime },
	})
	if err != nil {
		t.Fatalf("BuildRDSIAMAuthToken STS AssumeRole failed: %v", err)
	}

	if seenAction != "AssumeRole" || seenRoleARN != "arn:aws:iam::123456789012:role/rds-connect" || seenExternalID != "ext-123" {
		t.Fatalf("unexpected STS form params: action=%q role=%q ext=%q", seenAction, seenRoleARN, seenExternalID)
	}
	if !strings.HasPrefix(seenAuthHeader, "AWS4-HMAC-SHA256 Credential=AKIA_BASE/20261118/us-west-2/sts/aws4_request") {
		t.Fatalf("expected SigV4 Authorization header on STS AssumeRole call, got %q", seenAuthHeader)
	}
	if !strings.Contains(tok, "X-Amz-Credential=ASIATEMPKEY123%2F20261118%2Fus-west-2%2Frds-db%2Faws4_request") {
		t.Fatalf("expected assumed role access key in RDS token, got %q", tok)
	}
	if !strings.Contains(tok, "X-Amz-Security-Token=tempSessionToken789") {
		t.Fatalf("expected STS session token in RDS token, got %q", tok)
	}
}

func TestBuildRDSIAMAuthToken_OIDCWebIdentityIRSA(t *testing.T) {
	fixedTime := time.Date(2026, 11, 18, 9, 30, 0, 0, time.UTC)
	tokenFile := filepath.Join(t.TempDir(), "oidc-token")
	if err := os.WriteFile(tokenFile, []byte("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.irsa-payload.sig"), 0o600); err != nil {
		t.Fatalf("write token file: %v", err)
	}

	var seenAction, seenWebToken string
	stsSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		seenAction = r.Form.Get("Action")
		seenWebToken = r.Form.Get("WebIdentityToken")

		w.Header().Set("Content-Type", "text/xml")
		_, _ = w.Write([]byte(`
<AssumeRoleWithWebIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <AssumeRoleWithWebIdentityResult>
    <Credentials>
      <AccessKeyId>ASIAIRSAKEY</AccessKeyId>
      <SecretAccessKey>irsaSecret</SecretAccessKey>
      <SessionToken>irsaSessionTok</SessionToken>
      <Expiration>2026-11-18T10:30:00Z</Expiration>
    </Credentials>
  </AssumeRoleWithWebIdentityResult>
</AssumeRoleWithWebIdentityResponse>`))
	}))
	defer stsSrv.Close()

	netPol, _ := network.NewPolicy(config.OutboundSSRFConfig{
		AllowPrivateNetworks: true,
		AllowInsecureHTTP:    true,
	})

	// Ambient env vars must NOT be read when AllowAmbientCloudIAM is false.
	t.Setenv("AWS_ROLE_ARN", "arn:aws:iam::999999999999:role/should-not-read")
	t.Setenv("AWS_WEB_IDENTITY_TOKEN_FILE", tokenFile)
	t.Setenv("AWS_REGION", "eu-west-1")

	if _, err := BuildRDSIAMAuthToken(context.Background(), RDSIAMConfig{
		Host:   "rds.example.internal",
		Region: "eu-west-1",
		DBUser: "pg_irsa",
	}); err == nil {
		t.Fatal("expected BuildRDSIAMAuthToken to reject ambient env credentials when AllowAmbientCloudIAM=false")
	}

	// Explicit IRSA config succeeds.
	tok, err := BuildRDSIAMAuthToken(context.Background(), RDSIAMConfig{
		Host:                 "rds.example.internal",
		Region:               "eu-west-1",
		DBUser:               "pg_irsa",
		RoleARN:              "arn:aws:iam::123456789012:role/irsa-rds",
		WebIdentityTokenFile: tokenFile,
		STSEndpoint:          stsSrv.URL,
		NetPolicy:            netPol,
		Now:                  func() time.Time { return fixedTime },
	})
	if err != nil {
		t.Fatalf("IRSA BuildRDSIAMAuthToken failed: %v", err)
	}
	if seenAction != "AssumeRoleWithWebIdentity" || !strings.Contains(seenWebToken, "irsa-payload") {
		t.Fatalf("unexpected IRSA STS params: action=%q token=%q", seenAction, seenWebToken)
	}
	if !strings.Contains(tok, "ASIAIRSAKEY") {
		t.Fatalf("expected IRSA credentials in token, got %q", tok)
	}
}

func TestRDSIAMTokenProvider_RefreshAndBeforeConnect(t *testing.T) {
	var nowMu sync.Mutex
	curNow := time.Date(2026, 11, 18, 9, 0, 0, 0, time.UTC)
	nowFn := func() time.Time {
		nowMu.Lock()
		defer nowMu.Unlock()
		return curNow
	}

	var stsCalls atomic.Int32
	stsSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := stsCalls.Add(1)
		now := nowFn()
		exp := now.Add(1 * time.Hour).Format(time.RFC3339)
		w.Header().Set("Content-Type", "text/xml")
		_, _ = w.Write([]byte(`
<AssumeRoleResponse>
  <AssumeRoleResult>
    <Credentials>
      <AccessKeyId>ASIAKEY_` + string(rune('0'+n)) + `</AccessKeyId>
      <SecretAccessKey>secret</SecretAccessKey>
      <SessionToken>sess</SessionToken>
      <Expiration>` + exp + `</Expiration>
    </Credentials>
  </AssumeRoleResult>
</AssumeRoleResponse>`))
	}))
	defer stsSrv.Close()

	netPol, _ := network.NewPolicy(config.OutboundSSRFConfig{
		AllowPrivateNetworks: true,
		AllowInsecureHTTP:    true,
	})

	provider, err := NewRDSIAMTokenProvider(RDSIAMConfig{
		Enabled:         true,
		Host:            "rds.internal",
		Port:            5432,
		Region:          "us-east-1",
		DBUser:          "iam_user",
		AccessKeyID:     "AKIA_BASE",
		SecretAccessKey: "SECRET_BASE",
		RoleARN:         "arn:aws:iam::123:role/db",
		STSEndpoint:     stsSrv.URL,
		NetPolicy:       netPol,
		Now:             nowFn,
	})
	if err != nil {
		t.Fatalf("NewRDSIAMTokenProvider: %v", err)
	}

	connCfg, err := pgx.ParseConfig("postgres://wrong_user@rds.internal:5432/appdb")
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}

	// First BeforeConnect populates token and user.
	if err := provider.BeforeConnect(context.Background(), connCfg); err != nil {
		t.Fatalf("BeforeConnect 1: %v", err)
	}
	tok1 := connCfg.Password
	if connCfg.User != "iam_user" || tok1 == "" {
		t.Fatalf("unexpected connCfg after BeforeConnect: user=%q password_len=%d", connCfg.User, len(tok1))
	}

	// Within 12m window, BeforeConnect reuses cached token.
	nowMu.Lock()
	curNow = curNow.Add(5 * time.Minute)
	nowMu.Unlock()
	if err := provider.BeforeConnect(context.Background(), connCfg); err != nil {
		t.Fatalf("BeforeConnect 2: %v", err)
	}
	if connCfg.Password != tok1 {
		t.Fatal("expected cached RDS IAM token to be reused within refresh window")
	}

	// Advance past 12m (into 3m refreshBefore window) -> mints fresh RDS token while reusing valid STS creds.
	nowMu.Lock()
	curNow = curNow.Add(8 * time.Minute) // total +13m
	nowMu.Unlock()
	if err := provider.BeforeConnect(context.Background(), connCfg); err != nil {
		t.Fatalf("BeforeConnect 3: %v", err)
	}
	if connCfg.Password == tok1 {
		t.Fatal("expected RDS IAM token to rotate proactively before 15m expiry")
	}
	if stsCalls.Load() != 1 {
		t.Fatalf("expected STS credentials to be reused while valid, got %d STS calls", stsCalls.Load())
	}

	// Verify configurePostgresPool attaches BeforeConnect when RDSIAM.Enabled is true.
	poolCfg, err := configurePostgresPool("postgres://iam_user@rds.internal:5432/appdb", PostgresPoolOptions{
		RDSIAM: &RDSIAMConfig{
			Enabled:         true,
			Region:          "us-east-1",
			AccessKeyID:     "AKIA_BASE",
			SecretAccessKey: "SECRET_BASE",
		},
	})
	if err != nil {
		t.Fatalf("configurePostgresPool with RDSIAM failed: %v", err)
	}
	if poolCfg.BeforeConnect == nil {
		t.Fatal("expected configurePostgresPool to install BeforeConnect hook for RDS IAM")
	}
}
