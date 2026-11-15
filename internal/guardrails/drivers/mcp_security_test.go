package drivers_test

import (
	"context"
	"testing"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/guardrails"
	"github.com/goroute-ai/ai-gateway-go/internal/guardrails/drivers"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCodeExecutionDriver_BlockStripFlagAndFencedCode(t *testing.T) {
	ctx := context.Background()

	t.Run("blocks default and custom code-execution tools across hooks", func(t *testing.T) {
		drv, err := drivers.NewCodeExecutionDriver(guardrails.DriverConfig{
			Definition: &domain.GuardrailDefinition{Name: "no-code-exec"},
			EffectiveConfig: map[string]any{
				"action":        "block",
				"blocked_tools": []string{"custom_shell_runner"},
				"allowed_tools": []string{"node_info"},
			},
		})
		require.NoError(t, err)
		assert.Equal(t, "block_code_execution", drv.Name())
		assert.Equal(t, []domain.GuardrailHook{
			domain.GuardrailHookPreCall,
			domain.GuardrailHookPostCall,
			domain.GuardrailHookPreMCPCall,
		}, drv.SupportedHooks())

		for _, toolName := range []string{"bash", "python", "exec", "run_command", "code_interpreter", "custom_shell_runner"} {
			res, evalErr := drv.Evaluate(ctx, &domain.GuardrailEvalInput{
				Hook: domain.GuardrailHookPostCall,
				ToolCalls: []domain.CanonicalToolCall{{
					ID:   "tc-1",
					Type: "function",
					Function: domain.CanonicalFunctionCall{
						Name:      toolName,
						Arguments: `{"cmd":"id"}`,
					},
				}},
			})
			require.NoError(t, evalErr)
			assert.Equal(t, domain.GuardrailDecisionBlock, res.Decision, "expected block for %s", toolName)
			require.NotEmpty(t, res.Violations)
		}

		// Allowed exemption and safe tool pass
		for _, safeTool := range []string{"node_info", "fetch_weather"} {
			res, evalErr := drv.Evaluate(ctx, &domain.GuardrailEvalInput{
				Hook: domain.GuardrailHookPreMCPCall,
				ToolCalls: []domain.CanonicalToolCall{{
					ID:   "tc-safe",
					Type: "mcp",
					Function: domain.CanonicalFunctionCall{
						Name:      safeTool,
						Arguments: `{}`,
					},
				}},
			})
			require.NoError(t, evalErr)
			assert.Equal(t, domain.GuardrailDecisionAllow, res.Decision, "expected allow for %s", safeTool)
		}

		// Declared code_interpreter tool blocked in pre_call
		res, evalErr := drv.Evaluate(ctx, &domain.GuardrailEvalInput{
			Hook: domain.GuardrailHookPreCall,
			Tools: []domain.CanonicalTool{{
				Type: "code_interpreter",
			}},
		})
		require.NoError(t, evalErr)
		assert.Equal(t, domain.GuardrailDecisionBlock, res.Decision)
	})

	t.Run("strips unsafe tool calls and fenced code blocks via Pipeline", func(t *testing.T) {
		repo := storage.NewMemoryRepository()
		require.NoError(t, repo.CreateOrganization(ctx, &domain.Organization{ID: "org-ce", Name: "org-ce"}))
		require.NoError(t, repo.CreateGuardrailDefinition(ctx, &domain.GuardrailDefinition{
			ID:         "def-ce-strip",
			OrgID:      "org-ce",
			Name:       "strip-code-exec",
			Provider:   drivers.ProviderCodeExecution,
			EventHooks: []domain.GuardrailHook{domain.GuardrailHookPreCall, domain.GuardrailHookPostCall},
			DefaultOn:  true,
			Precedence: 1,
			Config: map[string]any{
				"action":             "strip",
				"detect_fenced_code": true,
			},
			Status: domain.GuardrailStatusActive,
		}))

		pipeline := guardrails.NewPipeline(nil, repo)
		pipeline.RegisterDriver(drivers.ProviderCodeExecution, func(_ context.Context, cfg guardrails.DriverConfig) (guardrails.Driver, error) {
			return drivers.NewCodeExecutionDriver(cfg)
		})

		req := &domain.CanonicalChatRequest{
			Model: "gpt-4o",
			Messages: []domain.CanonicalMessage{{
				Role:    "user",
				Content: "Please run:\n```bash\nrm -rf /tmp/test\n```\nand check weather",
				ToolCalls: []domain.CanonicalToolCall{
					{ID: "tc-bad", Type: "function", Function: domain.CanonicalFunctionCall{Name: "bash", Arguments: `{"cmd":"whoami"}`}},
					{ID: "tc-good", Type: "function", Function: domain.CanonicalFunctionCall{Name: "get_weather", Arguments: `{"city":"NYC"}`}},
				},
			}},
		}

		out, err := pipeline.EvaluatePreCall(ctx, guardrails.PipelineRequestContext{OrgID: "org-ce"}, req)
		require.NoError(t, err)
		assert.True(t, out.Redacted)
		assert.NotContains(t, req.Messages[0].Content, "rm -rf")
		assert.Contains(t, req.Messages[0].Content, "[CODE_EXECUTION_STRIPPED]")
		require.Len(t, req.Messages[0].ToolCalls, 1)
		assert.Equal(t, "get_weather", req.Messages[0].ToolCalls[0].Function.Name)

		// Post-call response stripping ALL unsafe tool calls removes them completely
		resp := &domain.CanonicalChatResponse{
			Choices: []domain.CanonicalChoice{{
				Index: 0,
				Message: domain.CanonicalMessage{
					Role:    "assistant",
					Content: "Executing python:\n```python\nimport os; os.system('id')\n```",
					ToolCalls: []domain.CanonicalToolCall{
						{ID: "tc-py", Type: "function", Function: domain.CanonicalFunctionCall{Name: "python_exec", Arguments: `{"code":"print(1)"}`}},
					},
				},
			}},
		}
		postOut, err := pipeline.EvaluatePostCall(ctx, guardrails.PipelineRequestContext{OrgID: "org-ce"}, resp)
		require.NoError(t, err)
		assert.True(t, postOut.Redacted)
		assert.Empty(t, resp.Choices[0].Message.ToolCalls)
		assert.NotContains(t, resp.Choices[0].Message.Content, "os.system")
		assert.Contains(t, resp.Choices[0].Message.Content, "[CODE_EXECUTION_STRIPPED]")
	})

	t.Run("flags without blocking when action is flag", func(t *testing.T) {
		drv, err := drivers.NewCodeExecutionDriver(guardrails.DriverConfig{
			EffectiveConfig: map[string]any{
				"action":             "flag",
				"detect_fenced_code": true,
			},
		})
		require.NoError(t, err)

		res, err := drv.Evaluate(ctx, &domain.GuardrailEvalInput{
			Hook:  domain.GuardrailHookPreCall,
			Texts: []string{"```python\nprint('hi')\n```"},
		})
		require.NoError(t, err)
		assert.Equal(t, domain.GuardrailDecisionFlag, res.Decision)
		require.Len(t, res.Violations, 1)
	})
}

func TestMCPSecurityDriver_RegistryAllowlistAndSSRF(t *testing.T) {
	ctx := context.Background()
	repo := storage.NewMemoryRepository()
	require.NoError(t, repo.CreateMCPServer(ctx, &domain.MCPServer{
		ID:          "srv-registered",
		OrgID:       "org-mcp",
		Name:        "Registered GitHub MCP",
		Slug:        "github-mcp",
		EndpointURL: "https://mcp.corp.example.com/github",
		IsActive:    true,
	}))
	require.NoError(t, repo.CreateMCPServer(ctx, &domain.MCPServer{
		ID:          "srv-inactive",
		OrgID:       "org-mcp",
		Name:        "Inactive MCP",
		Slug:        "inactive-mcp",
		EndpointURL: "https://inactive.corp.example.com/mcp",
		IsActive:    false,
	}))
	require.NoError(t, repo.CreateMCPServer(ctx, &domain.MCPServer{
		ID:          "srv-other-org",
		OrgID:       "org-other",
		Name:        "Other Org MCP",
		Slug:        "other-org-mcp",
		EndpointURL: "https://other.corp.example.com/mcp",
		IsActive:    true,
	}))

	drv, err := drivers.NewMCPSecurityDriver(guardrails.DriverConfig{
		Definition: &domain.GuardrailDefinition{Name: "mcp-sec"},
		EffectiveConfig: map[string]any{
			"action":              "block",
			"allowed_server_urls": []string{"https://partner.example.com/mcp/*"},
			"enforce_ssrf":        true,
		},
	}, repo)
	require.NoError(t, err)

	// 1. Registered tenant MCP server URL in LLM tool declaration -> allow
	res, err := drv.Evaluate(ctx, &domain.GuardrailEvalInput{
		OrgID: "org-mcp",
		Hook:  domain.GuardrailHookPreCall,
		Tools: []domain.CanonicalTool{{
			Type: "mcp",
			Function: domain.CanonicalFunction{
				Name: "github",
				Parameters: map[string]any{
					"server_label": "github-mcp",
					"server_url":   "https://mcp.corp.example.com/github/",
				},
			},
		}},
	})
	require.NoError(t, err)
	assert.Equal(t, domain.GuardrailDecisionAllow, res.Decision)

	// 2. Explicit allowlist wildcard URL -> allow
	res, err = drv.Evaluate(ctx, &domain.GuardrailEvalInput{
		OrgID: "org-mcp",
		Hook:  domain.GuardrailHookPreCall,
		Tools: []domain.CanonicalTool{{
			Type: "mcp",
			Function: domain.CanonicalFunction{
				Name: "partner",
				Parameters: map[string]any{
					"server_label": "partner-tools",
					"server_url":   "https://partner.example.com/mcp/v1",
				},
			},
		}},
	})
	require.NoError(t, err)
	assert.Equal(t, domain.GuardrailDecisionAllow, res.Decision)

	// 3. Unregistered external MCP server_url -> block
	res, err = drv.Evaluate(ctx, &domain.GuardrailEvalInput{
		OrgID: "org-mcp",
		Hook:  domain.GuardrailHookPreCall,
		Tools: []domain.CanonicalTool{{
			Type: "mcp",
			Function: domain.CanonicalFunction{
				Name: "evil",
				Parameters: map[string]any{
					"server_label": "evil-mcp",
					"server_url":   "https://attacker.example.net/mcp",
				},
			},
		}},
	})
	require.NoError(t, err)
	assert.Equal(t, domain.GuardrailDecisionBlock, res.Decision)
	assert.Equal(t, "untrusted_mcp_server", res.Violations[0].Rule)

	// 4. Label spoofing (registered label paired with attacker URL) -> block
	res, err = drv.Evaluate(ctx, &domain.GuardrailEvalInput{
		OrgID: "org-mcp",
		Hook:  domain.GuardrailHookPreCall,
		Tools: []domain.CanonicalTool{{
			Type: "mcp",
			Function: domain.CanonicalFunction{
				Name: "spoof",
				Parameters: map[string]any{
					"server_label": "github-mcp",
					"server_url":   "https://attacker.example.net/mcp",
				},
			},
		}},
	})
	require.NoError(t, err)
	assert.Equal(t, domain.GuardrailDecisionBlock, res.Decision)
	assert.Equal(t, "mcp_server_url_mismatch", res.Violations[0].Rule)

	// 5. Cross-org isolation and inactive server -> block
	for _, url := range []string{"https://inactive.corp.example.com/mcp", "https://other.corp.example.com/mcp"} {
		res, err = drv.Evaluate(ctx, &domain.GuardrailEvalInput{
			OrgID: "org-mcp",
			Hook:  domain.GuardrailHookPreMCPCall,
			Metadata: map[string]any{
				"mcp_server_url": url,
			},
		})
		require.NoError(t, err)
		assert.Equal(t, domain.GuardrailDecisionBlock, res.Decision)
	}

	// 6. SSRF / insecure scheme enforcement
	for _, badURL := range []string{
		"http://mcp.corp.example.com/github",
		"https://169.254.169.254/latest/meta-data",
		"https://127.0.0.1:8443/mcp",
	} {
		res, err = drv.Evaluate(ctx, &domain.GuardrailEvalInput{
			OrgID: "org-mcp",
			Hook:  domain.GuardrailHookPreMCPCall,
			Metadata: map[string]any{
				"mcp_server_url": badURL,
			},
		})
		require.NoError(t, err)
		assert.Equal(t, domain.GuardrailDecisionBlock, res.Decision)
		assert.Equal(t, "mcp_ssrf_blocked", res.Violations[0].Rule)
	}
}

func TestMCPEndUserPermissionDriver_UserRoleTeamAndOIDCClaims(t *testing.T) {
	ctx := context.Background()
	drv, err := drivers.NewMCPEndUserPermissionDriver(guardrails.DriverConfig{
		Definition: &domain.GuardrailDefinition{Name: "mcp-rbac"},
		EffectiveConfig: map[string]any{
			"action":         "block",
			"default_action": "deny",
			"rules": []map[string]any{
				{
					"server":          "billing-mcp",
					"tool":            "refund_*",
					"allowed_roles":   []string{"finance_admin"},
					"allowed_teams":   []string{"team-fin"},
					"required_claims": map[string]any{"dept": "finance", "scope": "mcp:write"},
				},
				{
					"server":        "docs-mcp",
					"tool":          "read_*",
					"allowed_users": []string{"alice", "bob"},
					"denied_users":  []string{"bob"},
				},
			},
		},
	})
	require.NoError(t, err)

	// 1. Authorized finance user with matching role, team, and OIDC claims -> allow
	res, err := drv.Evaluate(ctx, &domain.GuardrailEvalInput{
		Hook:      domain.GuardrailHookPreMCPCall,
		EndUserID: "usr-fin-1",
		TeamID:    "team-fin",
		ToolCalls: []domain.CanonicalToolCall{{
			Type:     "mcp",
			Function: domain.CanonicalFunctionCall{Name: "refund_invoice"},
		}},
		Metadata: map[string]any{
			"mcp_server_slug": "billing-mcp",
			"caller_roles":    []string{"finance_admin"},
			"oidc_claims": map[string]any{
				"dept":  "finance",
				"scope": "openid profile mcp:write",
			},
		},
	})
	require.NoError(t, err)
	assert.Equal(t, domain.GuardrailDecisionAllow, res.Decision)

	// 2. Wrong role -> block
	res, err = drv.Evaluate(ctx, &domain.GuardrailEvalInput{
		Hook:      domain.GuardrailHookPreMCPCall,
		EndUserID: "usr-dev-1",
		TeamID:    "team-fin",
		ToolCalls: []domain.CanonicalToolCall{{
			Type:     "mcp",
			Function: domain.CanonicalFunctionCall{Name: "refund_invoice"},
		}},
		Metadata: map[string]any{
			"mcp_server_slug": "billing-mcp",
			"caller_roles":    []string{"developer"},
			"oidc_claims":     map[string]any{"dept": "finance", "scope": "mcp:write"},
		},
	})
	require.NoError(t, err)
	assert.Equal(t, domain.GuardrailDecisionBlock, res.Decision)
	assert.Equal(t, "role_not_allowed", res.Violations[0].Rule)

	// 3. Missing OIDC claim -> block
	res, err = drv.Evaluate(ctx, &domain.GuardrailEvalInput{
		Hook:      domain.GuardrailHookPreMCPCall,
		EndUserID: "usr-fin-1",
		TeamID:    "team-fin",
		ToolCalls: []domain.CanonicalToolCall{{
			Type:     "mcp",
			Function: domain.CanonicalFunctionCall{Name: "refund_invoice"},
		}},
		Metadata: map[string]any{
			"mcp_server_slug": "billing-mcp",
			"caller_roles":    []string{"finance_admin"},
			"oidc_claims":     map[string]any{"dept": "engineering", "scope": "mcp:write"},
		},
	})
	require.NoError(t, err)
	assert.Equal(t, domain.GuardrailDecisionBlock, res.Decision)
	assert.Equal(t, "oidc_claim_denied", res.Violations[0].Rule)

	// 4. Denied user takes precedence -> block; allowed user -> allow
	res, err = drv.Evaluate(ctx, &domain.GuardrailEvalInput{
		Hook:      domain.GuardrailHookPreMCPCall,
		EndUserID: "bob",
		Metadata:  map[string]any{"mcp_server_slug": "docs-mcp", "mcp_tool_name": "read_spec"},
	})
	require.NoError(t, err)
	assert.Equal(t, domain.GuardrailDecisionBlock, res.Decision)
	assert.Equal(t, "denied_user", res.Violations[0].Rule)

	res, err = drv.Evaluate(ctx, &domain.GuardrailEvalInput{
		Hook:      domain.GuardrailHookPreMCPCall,
		EndUserID: "alice",
		Metadata:  map[string]any{"mcp_server_slug": "docs-mcp", "mcp_tool_name": "read_spec"},
	})
	require.NoError(t, err)
	assert.Equal(t, domain.GuardrailDecisionAllow, res.Decision)

	// 5. Unmatched server/tool falls back to default_action: deny -> block
	res, err = drv.Evaluate(ctx, &domain.GuardrailEvalInput{
		Hook:      domain.GuardrailHookPreMCPCall,
		EndUserID: "alice",
		Metadata:  map[string]any{"mcp_server_slug": "unknown-mcp", "mcp_tool_name": "drop_table"},
	})
	require.NoError(t, err)
	assert.Equal(t, domain.GuardrailDecisionBlock, res.Decision)
	assert.Equal(t, "default_deny", res.Violations[0].Rule)
}
