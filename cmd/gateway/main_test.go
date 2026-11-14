package main

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestRunMigrationsOnlyErrors(t *testing.T) {
	t.Run("empty dsn", func(t *testing.T) {
		err := runMigrationsOnly(context.Background(), "", "migrations")
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

		err := runMigrationsOnly(ctx, "postgres://gateway:gateway@127.0.0.1:1/aigateway?sslmode=disable", "migrations")
		if err == nil {
			t.Fatal("expected error for unreachable PostgreSQL, got nil")
		}
	})
}
