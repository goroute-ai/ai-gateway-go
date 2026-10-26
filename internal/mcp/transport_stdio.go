package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/auth/upstream"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
)

var (
	ErrBinaryNotAllowed   = errors.New("mcp: stdio binary is not in approved allowlist")
	ErrStdioProcessFailed = errors.New("mcp: stdio subprocess failed")
)

// StdioSecurityPolicy defines the sandboxing and allowlist rules for subprocess execution.
type StdioSecurityPolicy struct {
	AllowedBinaries []string      `json:"allowed_binaries"`
	DefaultTimeout  time.Duration `json:"default_timeout"`
	MaxOutputBytes  int64         `json:"max_output_bytes"`
}

// StdioTransport executes local tools via isolated stdio subprocesses.
type StdioTransport struct {
	policy StdioSecurityPolicy
	mu     sync.Mutex
}

// NewStdioTransport creates a new StdioTransport with the given security policy.
func NewStdioTransport(policy StdioSecurityPolicy) *StdioTransport {
	if policy.DefaultTimeout <= 0 {
		policy.DefaultTimeout = 30 * time.Second
	}
	if policy.MaxOutputBytes <= 0 {
		policy.MaxOutputBytes = 10 * 1024 * 1024 // 10MB
	}
	return &StdioTransport{
		policy: policy,
	}
}

// parseCommandLine splits a command string into arguments respecting single, double quotes, and backslash escapes.
func parseCommandLine(cmdStr string) []string {
	var args []string
	var current strings.Builder
	inQuote := false
	var quoteChar rune
	isEscaped := false

	for _, r := range cmdStr {
		if isEscaped {
			current.WriteRune(r)
			isEscaped = false
			continue
		}
		if r == '\\' {
			isEscaped = true
			continue
		}
		switch {
		case !inQuote && (r == '\'' || r == '"'):
			inQuote = true
			quoteChar = r
		case inQuote && r == quoteChar:
			inQuote = false
			quoteChar = 0
		case !inQuote && (r == ' ' || r == '\t'):
			if current.Len() > 0 {
				args = append(args, current.String())
				current.Reset()
			}
		default:
			current.WriteRune(r)
		}
	}
	if current.Len() > 0 {
		args = append(args, current.String())
	}
	return args
}

// isBinaryAllowed checks if the binary name or path is in the approved allowlist.
func (t *StdioTransport) isBinaryAllowed(binaryPath string) bool {
	if len(t.policy.AllowedBinaries) == 0 {
		return false
	}
	base := filepath.Base(binaryPath)
	for _, allowed := range t.policy.AllowedBinaries {
		if allowed == "*" || allowed == binaryPath || allowed == base {
			return true
		}
	}
	return false
}

// RoundTrip dispatches a single JSON-RPC request to the stdio subprocess and reads the response.
func (t *StdioTransport) RoundTrip(
	ctx context.Context,
	server *domain.MCPServer,
	authStrategy upstream.Strategy,
	authCtx *upstream.UpstreamAuthContext,
	reqBytes []byte,
	clientHeaders http.Header,
) (*JSONRPCResponse, http.Header, error) {
	if server == nil {
		return nil, nil, errors.New("mcp stdio: nil server")
	}

	rawCmd := strings.TrimPrefix(server.EndpointURL, "stdio://")
	args := parseCommandLine(rawCmd)
	if len(args) == 0 {
		return nil, nil, errors.New("mcp stdio: empty command")
	}

	binaryPath := args[0]
	if !t.isBinaryAllowed(binaryPath) {
		return nil, nil, fmt.Errorf("%w: %q", ErrBinaryNotAllowed, binaryPath)
	}

	execCtx, cancel := context.WithTimeout(ctx, t.policy.DefaultTimeout)
	defer cancel()

	cmd := exec.CommandContext(execCtx, args[0], args[1:]...)

	// Scrub environment variables: strictly isolate process from gateway master keys and secrets
	cmd.Env = []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + os.Getenv("HOME"),
		"LANG=en_US.UTF-8",
		"GOROUTE_SANDBOX=1",
	}

	// Apply static headers as environment variables if configured
	for k, v := range server.StaticHeaders {
		safeKey := strings.ToUpper(strings.ReplaceAll(k, "-", "_"))
		cmd.Env = append(cmd.Env, safeKey+"="+v)
	}

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, nil, fmt.Errorf("mcp stdio: open stdin: %w", err)
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, nil, fmt.Errorf("mcp stdio: open stdout: %w", err)
	}

	stderr, _ := cmd.StderrPipe()

	if err := cmd.Start(); err != nil {
		return nil, nil, fmt.Errorf("mcp stdio: start process: %w", err)
	}

	// Write newline-delimited JSON-RPC request
	go func() {
		defer stdin.Close()
		_, _ = stdin.Write(reqBytes)
		_, _ = stdin.Write([]byte("\n"))
	}()

	// Read response from stdout
	maxOut := int(t.policy.MaxOutputBytes)
	if maxOut < 2*1024*1024 {
		maxOut = 2 * 1024 * 1024
	}
	scanner := bufio.NewScanner(io.LimitReader(stdout, t.policy.MaxOutputBytes))
	scanner.Buffer(make([]byte, 64*1024), maxOut)
	var responseLine string
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			responseLine = line
			break
		}
	}

	// Drain stderr in background for error reporting if process fails
	var errOutput strings.Builder
	if stderr != nil {
		go func() {
			errScanner := bufio.NewScanner(io.LimitReader(stderr, 4096))
			for errScanner.Scan() {
				errOutput.WriteString(errScanner.Text() + "\n")
			}
		}()
	}

	_ = cmd.Wait()

	if responseLine == "" {
		errMsg := errOutput.String()
		if errMsg != "" {
			return nil, nil, fmt.Errorf("%w: process exited without response (stderr: %s)", ErrStdioProcessFailed, strings.TrimSpace(errMsg))
		}
		return nil, nil, fmt.Errorf("%w: process exited without producing JSON-RPC output", ErrStdioProcessFailed)
	}

	var jsonRPCResp JSONRPCResponse
	if err := json.Unmarshal([]byte(responseLine), &jsonRPCResp); err != nil {
		return nil, nil, fmt.Errorf("mcp stdio: decode json-rpc response: %w (raw: %s)", err, responseLine)
	}

	return &jsonRPCResp, http.Header{}, nil
}
