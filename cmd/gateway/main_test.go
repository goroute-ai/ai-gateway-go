package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
)

func TestRunMigrationsOnlyErrors(t *testing.T) {
	t.Run("empty dsn", func(t *testing.T) {
		err := runMigrationsOnly(context.Background(), "", "migrations", storage.PostgresPoolOptions{})
		if err == nil {
			t.Fatal("expected error for empty DSN, got nil")
		}
		if !strings.Contains(err.Error(), "postgres DSN is required") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("unreachable postgres", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		defer cancel()

		err := runMigrationsOnly(ctx, "postgres://gateway:gateway@127.0.0.1:1/aigateway?sslmode=disable", "migrations", storage.PostgresPoolOptions{})
		if err == nil {
			t.Fatal("expected error for unreachable PostgreSQL, got nil")
		}
	})
}

func TestPostgresPoolOptions_RDSIAM(t *testing.T) {
	cfg := config.Default()
	cfg.Auth.AllowAmbientCloudIAM = true
	cfg.Storage.RDSIAM = config.RDSIAMConfig{
		Enabled: true,
		Region:  "us-west-2",
		RoleARN: "arn:aws:iam::123456789012:role/gw-db",
	}
	opts, err := postgresPoolOptions(cfg)
	if err != nil {
		t.Fatalf("postgresPoolOptions: %v", err)
	}
	if opts.RDSIAM == nil || !opts.RDSIAM.Enabled || !opts.RDSIAM.AllowAmbientCloudIAM || opts.RDSIAM.Region != "us-west-2" {
		t.Fatalf("unexpected RDSIAM options: %+v", opts.RDSIAM)
	}
}
