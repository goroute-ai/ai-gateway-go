package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

func main() {
	if err := run(context.Background(), os.Args[1:], os.Stdout, os.Stderr); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		printUsage(stderr)
		return nil
	}
	switch args[0] {
	case "login":
		return cmdLogin(ctx, args[1:], stdout)
	case "logout":
		return cmdLogout(ctx, args[1:], stdout)
	case "whoami":
		return cmdWhoami(ctx, stdout)
	case "models":
		return cmdModels(ctx, args[1:], stdout)
	case "keys":
		return cmdKeys(ctx, args[1:], stdout)
	case "projects":
		return cmdProjects(ctx, args[1:], stdout)
	case "-h", "--help", "help":
		printUsage(stdout)
		return nil
	default:
		printUsage(stderr)
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func printUsage(w io.Writer) {
	_, _ = fmt.Fprintln(w, `goroute - GoRoute AI Gateway Developer CLI

Usage:
  goroute login --gateway <url> [--provider <id>] [--no-open] [--print-key]
  goroute logout [--revoke]
  goroute whoami
  goroute models list
  goroute keys list|create|rotate|revoke [flags]
  goroute projects list [--team <team_id>]`)
}

func cmdLogin(ctx context.Context, args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("login", flag.ContinueOnError)
	gatewayURL := fs.String("gateway", strings.TrimSpace(os.Getenv("GOROUTE_URL")), "Gateway base URL (e.g. https://gateway.example.com)")
	provider := fs.String("provider", "", "Optional SSO provider ID")
	noOpen := fs.Bool("no-open", false, "Do not automatically open the browser")
	printKey := fs.Bool("print-key", false, "Print the minted API key to stdout (disabled by default for safety)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*gatewayURL) == "" {
		return fmt.Errorf("--gateway URL is required (or set GOROUTE_URL)")
	}
	client := newAPIClient(*gatewayURL, "")
	creds, err := runDeviceLogin(ctx, client, *provider, !*noOpen, stdout)
	if err != nil {
		return err
	}
	path, err := saveCredentials(*creds)
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintf(stdout, "Authenticated successfully!\n  Gateway: %s\n  Org:     %s\n  Key:     %s\n  Saved:   %s (0600)\n",
		creds.GatewayURL, creds.OrgID, creds.KeyPrefix, path)
	if *printKey {
		_, _ = fmt.Fprintf(stdout, "API Key: %s\n", creds.APIKey)
	}
	return nil
}

func cmdLogout(ctx context.Context, args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("logout", flag.ContinueOnError)
	revoke := fs.Bool("revoke", false, "Also revoke the stored CLI virtual key on the gateway")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *revoke {
		if creds, err := loadCredentials(); err == nil && creds.KeyID != "" {
			c := newAPIClient(creds.GatewayURL, creds.APIKey)
			_, _, _ = c.doJSON(ctx, http.MethodPost, "/admin/v1/keys/"+creds.KeyID+"/revoke", nil, nil)
		}
	}
	if err := clearCredentials(); err != nil {
		return err
	}
	_, _ = fmt.Fprintln(stdout, "Cleared stored GoRoute CLI credentials.")
	return nil
}

func cmdWhoami(ctx context.Context, stdout io.Writer) error {
	creds, err := loadCredentials()
	if err != nil {
		return err
	}
	client := newAPIClient(creds.GatewayURL, creds.APIKey)
	var me map[string]any
	if _, _, err := client.doJSON(ctx, http.MethodGet, "/auth/me", nil, &me); err == nil {
		return writePrettyJSON(stdout, me)
	}
	var keyInfo map[string]any
	if _, _, err := client.doJSON(ctx, http.MethodGet, "/v1/key/info", nil, &keyInfo); err == nil {
		return writePrettyJSON(stdout, keyInfo)
	}
	var models map[string]any
	if _, _, err := client.doJSON(ctx, http.MethodGet, "/v1/models", nil, &models); err != nil {
		return fmt.Errorf("verify credentials: %w", err)
	}
	return writePrettyJSON(stdout, map[string]any{
		"gateway_url": creds.GatewayURL,
		"org_id":      creds.OrgID,
		"team_id":     creds.TeamID,
		"key_prefix":  creds.KeyPrefix,
		"models":      models["data"],
	})
}

func cmdModels(ctx context.Context, args []string, stdout io.Writer) error {
	if len(args) == 0 || args[0] != "list" {
		return fmt.Errorf("usage: goroute models list")
	}
	creds, err := loadCredentials()
	if err != nil {
		return err
	}
	client := newAPIClient(creds.GatewayURL, creds.APIKey)
	var resp map[string]any
	if _, _, err := client.doJSON(ctx, http.MethodGet, "/v1/models", nil, &resp); err != nil {
		return err
	}
	return writePrettyJSON(stdout, resp)
}

func cmdKeys(ctx context.Context, args []string, stdout io.Writer) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: goroute keys list|create|rotate|revoke")
	}
	creds, err := loadCredentials()
	if err != nil {
		return err
	}
	client := newAPIClient(creds.GatewayURL, creds.APIKey)
	switch args[0] {
	case "list":
		var resp map[string]any
		path := "/admin/v1/keys"
		if creds.OrgID != "" {
			path += "?org_id=" + creds.OrgID
		}
		if _, _, err := client.doJSON(ctx, http.MethodGet, path, nil, &resp); err != nil {
			return err
		}
		return writePrettyJSON(stdout, resp)
	case "create":
		fs := flag.NewFlagSet("keys create", flag.ContinueOnError)
		name := fs.String("name", "", "Key name (required)")
		teamID := fs.String("team", creds.TeamID, "Team ID")
		projectID := fs.String("project", "", "Project ID")
		modelsCSV := fs.String("models", "", "Comma-separated allowed models")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if strings.TrimSpace(*name) == "" {
			return fmt.Errorf("--name is required")
		}
		body := map[string]any{
			"org_id":     creds.OrgID,
			"name":       strings.TrimSpace(*name),
			"team_id":    strings.TrimSpace(*teamID),
			"project_id": strings.TrimSpace(*projectID),
		}
		if strings.TrimSpace(*modelsCSV) != "" {
			var list []string
			for _, m := range strings.Split(*modelsCSV, ",") {
				if t := strings.TrimSpace(m); t != "" {
					list = append(list, t)
				}
			}
			body["allowed_models"] = list
		}
		var resp map[string]any
		if _, _, err := client.doJSON(ctx, http.MethodPost, "/admin/v1/keys", body, &resp); err != nil {
			return err
		}
		return writePrettyJSON(stdout, resp)
	case "rotate":
		if len(args) < 2 {
			return fmt.Errorf("usage: goroute keys rotate <key_id>")
		}
		var resp map[string]any
		if _, _, err := client.doJSON(ctx, http.MethodPost, "/admin/v1/keys/"+args[1]+"/rotate", map[string]any{"org_id": creds.OrgID}, &resp); err != nil {
			return err
		}
		return writePrettyJSON(stdout, resp)
	case "revoke":
		if len(args) < 2 {
			return fmt.Errorf("usage: goroute keys revoke <key_id>")
		}
		var resp map[string]any
		if _, _, err := client.doJSON(ctx, http.MethodPost, "/admin/v1/keys/"+args[1]+"/revoke", nil, &resp); err != nil {
			return err
		}
		return writePrettyJSON(stdout, resp)
	default:
		return fmt.Errorf("unknown keys subcommand %q", args[0])
	}
}

func cmdProjects(ctx context.Context, args []string, stdout io.Writer) error {
	if len(args) == 0 || args[0] != "list" {
		return fmt.Errorf("usage: goroute projects list [--team <team_id>]")
	}
	fs := flag.NewFlagSet("projects list", flag.ContinueOnError)
	teamID := fs.String("team", "", "Filter by team ID")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	creds, err := loadCredentials()
	if err != nil {
		return err
	}
	client := newAPIClient(creds.GatewayURL, creds.APIKey)
	path := "/admin/v1/projects?org_id=" + creds.OrgID
	if strings.TrimSpace(*teamID) != "" {
		path += "&team_id=" + strings.TrimSpace(*teamID)
	}
	var resp map[string]any
	if _, _, err := client.doJSON(ctx, http.MethodGet, path, nil, &resp); err != nil {
		return err
	}
	return writePrettyJSON(stdout, resp)
}

func writePrettyJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
