package storage

import (
	"context"
	"path/filepath"
	"testing"
)

func TestRunMigrations_ErrorsWithoutPoolOrDir(t *testing.T) {
	ctx := context.Background()

	if err := RunMigrations(ctx, nil, "0001_init.up.sql"); err == nil {
		t.Fatal("expected error when pool is nil in RunMigrations")
	}
	if err := RunMigrationsDir(ctx, nil, t.TempDir()); err == nil {
		t.Fatal("expected error when pool is nil in RunMigrationsDir")
	}
	if err := RunMigrationsDir(ctx, nil, filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("expected error when migrations dir does not exist")
	}
}
