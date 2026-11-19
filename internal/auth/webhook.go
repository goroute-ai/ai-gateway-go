package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/security/network"
)

func dispatchLifecycleWebhook(
	ctx context.Context,
	client *http.Client,
	netPolicy *network.Policy,
	rawURL string,
	payload any,
) error {
	trimmed := strings.TrimSpace(rawURL)
	if trimmed == "" {
		return nil
	}
	parsed, err := url.Parse(trimmed)
	if err != nil {
		return err
	}
	if netPolicy != nil {
		if err := netPolicy.ValidateURL(parsed); err != nil {
			return err
		}
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	if client == nil {
		client = network.NewHTTPClient(netPolicy)
	}
	reqCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, parsed.String(), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	_ = resp.Body.Close()
	if resp.StatusCode >= 300 {
		return errors.New("lifecycle webhook returned non-2xx status: " + resp.Status)
	}
	return nil
}
