package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Credentials holds locally persisted CLI authentication metadata stored with 0600 permissions.
type Credentials struct {
	GatewayURL string    `json:"gateway_url"`
	APIKey     string    `json:"api_key"`
	KeyID      string    `json:"key_id,omitempty"`
	KeyPrefix  string    `json:"key_prefix,omitempty"`
	OrgID      string    `json:"org_id,omitempty"`
	TeamID     string    `json:"team_id,omitempty"`
	SavedAt    time.Time `json:"saved_at"`
}

func credentialsFilePath() (string, error) {
	if customDir := strings.TrimSpace(os.Getenv("GOROUTE_CONFIG_DIR")); customDir != "" {
		return filepath.Join(customDir, "credentials.json"), nil
	}
	base, err := os.UserConfigDir()
	if err != nil {
		home, hErr := os.UserHomeDir()
		if hErr != nil {
			return "", fmt.Errorf("resolve config dir: %w", err)
		}
		base = filepath.Join(home, ".config")
	}
	return filepath.Join(base, "goroute", "credentials.json"), nil
}

func saveCredentials(creds Credentials) (string, error) {
	path, err := credentialsFilePath()
	if err != nil {
		return "", err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("create credentials dir: %w", err)
	}
	creds.GatewayURL = strings.TrimRight(strings.TrimSpace(creds.GatewayURL), "/")
	if creds.SavedAt.IsZero() {
		creds.SavedAt = time.Now().UTC()
	}
	data, err := json.MarshalIndent(creds, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshal credentials: %w", err)
	}
	data = append(data, '\n')

	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return "", fmt.Errorf("write temp credentials: %w", err)
	}
	if err := os.Chmod(tmp, 0o600); err != nil {
		_ = os.Remove(tmp)
		return "", fmt.Errorf("chmod temp credentials: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return "", fmt.Errorf("commit credentials file: %w", err)
	}
	return path, nil
}

func loadCredentials() (*Credentials, error) {
	var creds Credentials
	path, err := credentialsFilePath()
	if err == nil {
		if raw, rErr := os.ReadFile(path); rErr == nil {
			_ = json.Unmarshal(raw, &creds)
		} else if !errors.Is(rErr, os.ErrNotExist) {
			return nil, fmt.Errorf("read credentials: %w", rErr)
		}
	}
	if envURL := strings.TrimSpace(os.Getenv("GOROUTE_URL")); envURL != "" {
		creds.GatewayURL = strings.TrimRight(envURL, "/")
	}
	if envKey := strings.TrimSpace(os.Getenv("GOROUTE_API_KEY")); envKey != "" {
		creds.APIKey = envKey
	}
	if creds.GatewayURL == "" || creds.APIKey == "" {
		return nil, errors.New("not authenticated: run `goroute login --gateway <url>` or set GOROUTE_URL and GOROUTE_API_KEY")
	}
	return &creds, nil
}

func clearCredentials() error {
	path, err := credentialsFilePath()
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}
