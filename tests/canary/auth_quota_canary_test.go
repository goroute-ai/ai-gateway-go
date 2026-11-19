//go:build canary

package canary_test

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/adapter/bedrock"
	"github.com/goroute-ai/ai-gateway-go/internal/adapter/vertex"
	"github.com/goroute-ai/ai-gateway-go/internal/auth"
	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/security/network"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
)

func TestCanary_ExternalOIDC_DiscoveryAndTokenValidation(t *testing.T) {
	issuer := strings.TrimSpace(os.Getenv("CANARY_OIDC_ISSUER"))
	bearer := strings.TrimSpace(os.Getenv("CANARY_OIDC_BEARER_TOKEN"))
	audience := strings.TrimSpace(os.Getenv("CANARY_OIDC_AUDIENCE"))
	if issuer == "" || bearer == "" {
		t.Skip("skipping external OIDC canary: CANARY_OIDC_ISSUER and CANARY_OIDC_BEARER_TOKEN not set")
	}

	netPol, err := network.NewPolicy(config.Default().Security.Network.OutboundSSRF)
	if err != nil {
		t.Fatalf("network.NewPolicy: %v", err)
	}

	verifier := auth.NewJWTVerifier(auth.JWTConfig{
		Issuers: []auth.OIDCIssuerConfig{{
			Issuer:        issuer,
			Audience:      audience,
			NetworkPolicy: netPol,
		}},
		NetworkPolicy: netPol,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	claims, err := verifier.Verify(ctx, bearer)
	if err != nil {
		t.Fatalf("verifier.Verify against external OIDC issuer %q failed: %v", issuer, err)
	}
	if strings.TrimSpace(claims.Subject) == "" {
		t.Fatalf("verified external OIDC token returned empty sub claim")
	}
}

func TestCanary_LiveCloudIAM_Bedrock_Vertex_RDS(t *testing.T) {
	netPol, err := network.NewPolicy(config.Default().Security.Network.OutboundSSRF)
	if err != nil {
		t.Fatalf("network.NewPolicy: %v", err)
	}

	t.Run("aws_bedrock", func(t *testing.T) {
		model := strings.TrimSpace(os.Getenv("CANARY_AWS_BEDROCK_MODEL"))
		if model == "" {
			t.Skip("skipping AWS Bedrock IAM canary: CANARY_AWS_BEDROCK_MODEL not set")
		}
		region := strings.TrimSpace(os.Getenv("CANARY_AWS_REGION"))
		if region == "" {
			region = "us-east-1"
		}
		prov := bedrock.NewAmbientCredentialProvider(bedrock.AmbientIAMConfig{
			AllowAmbientCloudIAM: true,
			Region:               region,
			SSRFPolicy:           netPol,
		})
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		creds, err := prov.GetCredentials(ctx)
		if err != nil {
			t.Fatalf("bedrock GetCredentials failed for model %q in %q: %v", model, region, err)
		}
		if creds.AccessKeyID == "" || creds.SecretAccessKey == "" {
			t.Fatalf("expected non-empty ambient AWS Bedrock credentials")
		}
	})

	t.Run("gcp_vertex", func(t *testing.T) {
		project := strings.TrimSpace(os.Getenv("CANARY_GCP_VERTEX_PROJECT"))
		model := strings.TrimSpace(os.Getenv("CANARY_GCP_VERTEX_MODEL"))
		if project == "" || model == "" {
			t.Skip("skipping GCP Vertex ADC canary: CANARY_GCP_VERTEX_PROJECT and CANARY_GCP_VERTEX_MODEL not set")
		}
		ts, err := vertex.NewAmbientTokenSource(vertex.AmbientADCConfig{
			AllowAmbientCloudIAM: true,
			SSRFPolicy:           netPol,
		})
		if err != nil {
			t.Fatalf("vertex.NewAmbientTokenSource failed for project %q: %v", project, err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		tok, err := ts.GetToken(ctx)
		if err != nil || strings.TrimSpace(tok) == "" {
			t.Fatalf("vertex GetToken failed for model %q: tok=%q err=%v", model, tok, err)
		}
	})

	t.Run("aws_rds_iam", func(t *testing.T) {
		endpoint := strings.TrimSpace(os.Getenv("CANARY_AWS_RDS_ENDPOINT"))
		region := strings.TrimSpace(os.Getenv("CANARY_AWS_RDS_REGION"))
		dbUser := strings.TrimSpace(os.Getenv("CANARY_AWS_RDS_USER"))
		if endpoint == "" || region == "" || dbUser == "" {
			t.Skip("skipping AWS RDS IAM canary: CANARY_AWS_RDS_ENDPOINT, CANARY_AWS_RDS_REGION, and CANARY_AWS_RDS_USER not set")
		}
		provider, err := storage.NewRDSIAMTokenProvider(storage.RDSIAMConfig{
			Enabled:              true,
			AllowAmbientCloudIAM: true,
			Host:                 endpoint,
			Port:                 5432,
			Region:               region,
			DBUser:               dbUser,
			NetPolicy:            netPol,
		})
		if err != nil {
			t.Fatalf("NewRDSIAMTokenProvider: %v", err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		tok, err := provider.Token(ctx)
		if err != nil || !strings.Contains(tok, "Action=connect") {
			t.Fatalf("RDS IAM Token failed: tok=%q err=%v", tok, err)
		}
	})
}
