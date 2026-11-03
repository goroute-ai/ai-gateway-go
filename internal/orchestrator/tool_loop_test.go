package orchestrator_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/adapter"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/mcp"
	"github.com/goroute-ai/ai-gateway-go/internal/orchestrator"
	"github.com/goroute-ai/ai-gateway-go/internal/router"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockInferenceApp struct {
	turns []func(req *domain.CanonicalChatRequest) (*domain.CanonicalChatResponse, *router.ExecutionMeta, error)
	index int
}

func (m *mockInferenceApp) ExecuteChat(
	ctx context.Context,
	idCtx *domain.IdentityContext,
	req *domain.CanonicalChatRequest,
) (*domain.CanonicalChatResponse, *router.ExecutionMeta, error) {
	if m.index >= len(m.turns) {
		return &domain.CanonicalChatResponse{
			Choices: []domain.CanonicalChoice{
				{
					Index:        0,
					FinishReason: "stop",
					Message: domain.CanonicalMessage{
						Role:    "assistant",
						Content: "Default completion",
					},
				},
			},
		}, &router.ExecutionMeta{}, nil
	}
	fn := m.turns[m.index]
	m.index++
	return fn(req)
}

func (m *mockInferenceApp) ExecuteStream(
	ctx context.Context,
	idCtx *domain.IdentityContext,
	req *domain.CanonicalChatRequest,
	onChunk adapter.StreamChunkHandler,
) (*domain.TokenUsage, *router.ExecutionMeta, error) {
	resp, meta, err := m.ExecuteChat(ctx, idCtx, req)
	if err != nil {
		return nil, meta, err
	}
	return &resp.Usage, meta, nil
}

type mockMCPHubApp struct {
	tools     []domain.MCPTool
	callLogs  []mcp.ToolCallInput
	callFuncs map[string]func(input mcp.ToolCallInput) (*mcp.CallToolResponse, error)
}

func (m *mockMCPHubApp) ListTools(ctx context.Context, idCtx *domain.IdentityContext, serverSlug string) ([]domain.MCPTool, error) {
	return m.tools, nil
}

func (m *mockMCPHubApp) CallTool(ctx context.Context, idCtx *domain.IdentityContext, input mcp.ToolCallInput, meta mcp.CallMetadata) (*mcp.CallToolResponse, error) {
	m.callLogs = append(m.callLogs, input)
	if fn, ok := m.callFuncs[input.ToolName]; ok {
		return fn(input)
	}
	return &mcp.CallToolResponse{
		Content: []mcp.ToolContent{
			{Type: "text", Text: "result for " + input.ToolName},
		},
	}, nil
}

func TestToolLoopOrchestrator_MultiTurnExecution(t *testing.T) {
	ctx := context.Background()
	idCtx := &domain.IdentityContext{
		OrgID:        "org_test",
		VirtualKeyID: "vk_test",
	}

	mcpHub := &mockMCPHubApp{
		tools: []domain.MCPTool{
			{Name: "get_weather", IsActive: true},
		},
		callFuncs: map[string]func(input mcp.ToolCallInput) (*mcp.CallToolResponse, error){
			"get_weather": func(input mcp.ToolCallInput) (*mcp.CallToolResponse, error) {
				return &mcp.CallToolResponse{
					Content: []mcp.ToolContent{
						{Type: "text", Text: "Sunny, 22°C in San Francisco"},
					},
				}, nil
			},
		},
	}

	infApp := &mockInferenceApp{
		turns: []func(req *domain.CanonicalChatRequest) (*domain.CanonicalChatResponse, *router.ExecutionMeta, error){
			// Turn 1: Model calls get_weather tool
			func(req *domain.CanonicalChatRequest) (*domain.CanonicalChatResponse, *router.ExecutionMeta, error) {
				return &domain.CanonicalChatResponse{
					ID:      "resp_turn_1",
					Created: time.Now().Unix(),
					Model:   "gpt-4o",
					Choices: []domain.CanonicalChoice{
						{
							Index:        0,
							FinishReason: "tool_calls",
							Message: domain.CanonicalMessage{
								Role: "assistant",
								ToolCalls: []domain.CanonicalToolCall{
									{
										ID:   "call_w1",
										Type: "function",
										Function: domain.CanonicalFunctionCall{
											Name:      "get_weather",
											Arguments: `{"city":"San Francisco"}`,
										},
									},
								},
							},
						},
					},
					Usage: domain.TokenUsage{PromptTokens: 20, CompletionTokens: 15, TotalTokens: 35},
				}, &router.ExecutionMeta{LatencyMs: 40}, nil
			},
			// Turn 2: Model receives weather observation and generates final text
			func(req *domain.CanonicalChatRequest) (*domain.CanonicalChatResponse, *router.ExecutionMeta, error) {
				// Verify conversation history has tool result injected
				require.Len(t, req.Messages, 3)
				assert.Equal(t, "tool", req.Messages[2].Role)
				assert.Equal(t, "call_w1", req.Messages[2].ToolCallID)
				assert.Contains(t, req.Messages[2].Content, "Sunny, 22°C")

				return &domain.CanonicalChatResponse{
					ID:      "resp_turn_2",
					Created: time.Now().Unix(),
					Model:   "gpt-4o",
					Choices: []domain.CanonicalChoice{
						{
							Index:        0,
							FinishReason: "stop",
							Message: domain.CanonicalMessage{
								Role:    "assistant",
								Content: "The current weather in San Francisco is sunny and 22°C.",
							},
						},
					},
					Usage: domain.TokenUsage{PromptTokens: 45, CompletionTokens: 20, TotalTokens: 65},
				}, &router.ExecutionMeta{LatencyMs: 35}, nil
			},
		},
	}

	orch := orchestrator.NewToolLoopOrchestrator(infApp, mcpHub, orchestrator.DefaultBudgetPolicy())

	chatReq := &domain.CanonicalChatRequest{
		Model: "gpt-4o",
		Messages: []domain.CanonicalMessage{
			{Role: "user", Content: "What's the weather in San Francisco?"},
		},
		Tools: []domain.CanonicalTool{
			{Type: "function", Function: domain.CanonicalFunction{Name: "get_weather"}},
		},
	}

	resp, meta, err := orch.ExecuteLoop(ctx, idCtx, chatReq)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.NotNil(t, meta)

	// Verify tool execution occurred
	require.Len(t, mcpHub.callLogs, 1)
	assert.Equal(t, "get_weather", mcpHub.callLogs[0].ToolName)
	assert.Equal(t, "San Francisco", mcpHub.callLogs[0].Arguments["city"])

	// Verify exact-once billing consolidation (20+45 prompt tokens, 15+20 completion tokens = 100 total)
	assert.Equal(t, 65, resp.Usage.PromptTokens)
	assert.Equal(t, 35, resp.Usage.CompletionTokens)
	assert.Equal(t, 100, resp.Usage.TotalTokens)

	// Verify final answer
	assert.Equal(t, "The current weather in San Francisco is sunny and 22°C.", resp.Choices[0].Message.Content)
	assert.Equal(t, "stop", resp.Choices[0].FinishReason)
	assert.Equal(t, "2", resp.Metadata["goroute.orchestrator/loop_rounds"])
	assert.Equal(t, "1", resp.Metadata["goroute.orchestrator/total_tool_calls"])
}

func TestToolLoopOrchestrator_SelfCorrectingJSON(t *testing.T) {
	ctx := context.Background()
	idCtx := &domain.IdentityContext{OrgID: "org_test"}

	mcpHub := &mockMCPHubApp{
		tools: []domain.MCPTool{
			{Name: "sql_query", IsActive: true},
		},
	}

	infApp := &mockInferenceApp{
		turns: []func(req *domain.CanonicalChatRequest) (*domain.CanonicalChatResponse, *router.ExecutionMeta, error){
			// Turn 1: Model emits malformed JSON arguments
			func(req *domain.CanonicalChatRequest) (*domain.CanonicalChatResponse, *router.ExecutionMeta, error) {
				return &domain.CanonicalChatResponse{
					Choices: []domain.CanonicalChoice{
						{
							Index:        0,
							FinishReason: "tool_calls",
							Message: domain.CanonicalMessage{
								Role: "assistant",
								ToolCalls: []domain.CanonicalToolCall{
									{
										ID:   "call_bad_json",
										Type: "function",
										Function: domain.CanonicalFunctionCall{
											Name:      "sql_query",
											Arguments: `{"query": "SELECT * FROM users WHERE id = `, // Truncated/malformed
										},
									},
								},
							},
						},
					},
					Usage: domain.TokenUsage{TotalTokens: 25},
				}, &router.ExecutionMeta{}, nil
			},
			// Turn 2: Verify error observation was injected, then model self-corrects with valid JSON
			func(req *domain.CanonicalChatRequest) (*domain.CanonicalChatResponse, *router.ExecutionMeta, error) {
				require.Len(t, req.Messages, 3)
				lastMsg := req.Messages[2]
				assert.Equal(t, "tool", lastMsg.Role)
				assert.Contains(t, lastMsg.Content, "Invalid JSON arguments")
				assert.Contains(t, lastMsg.Content, "Please format arguments as valid JSON")

				// Model self-corrects
				return &domain.CanonicalChatResponse{
					Choices: []domain.CanonicalChoice{
						{
							Index:        0,
							FinishReason: "tool_calls",
							Message: domain.CanonicalMessage{
								Role: "assistant",
								ToolCalls: []domain.CanonicalToolCall{
									{
										ID:   "call_corrected",
										Type: "function",
										Function: domain.CanonicalFunctionCall{
											Name:      "sql_query",
											Arguments: `{"query": "SELECT * FROM users WHERE id = 42"}`,
										},
									},
								},
							},
						},
					},
					Usage: domain.TokenUsage{TotalTokens: 30},
				}, &router.ExecutionMeta{}, nil
			},
			// Turn 3: Model outputs final answer
			func(req *domain.CanonicalChatRequest) (*domain.CanonicalChatResponse, *router.ExecutionMeta, error) {
				return &domain.CanonicalChatResponse{
					Choices: []domain.CanonicalChoice{
						{
							Index:        0,
							FinishReason: "stop",
							Message: domain.CanonicalMessage{
								Role:    "assistant",
								Content: "User ID 42 is Alice.",
							},
						},
					},
					Usage: domain.TokenUsage{TotalTokens: 20},
				}, &router.ExecutionMeta{}, nil
			},
		},
	}

	orch := orchestrator.NewToolLoopOrchestrator(infApp, mcpHub, orchestrator.DefaultBudgetPolicy())

	chatReq := &domain.CanonicalChatRequest{
		Model: "gpt-4o",
		Messages: []domain.CanonicalMessage{
			{Role: "user", Content: "Find user 42"},
		},
		Tools: []domain.CanonicalTool{
			{Type: "function", Function: domain.CanonicalFunction{Name: "sql_query"}},
		},
	}

	resp, _, err := orch.ExecuteLoop(ctx, idCtx, chatReq)
	require.NoError(t, err)
	assert.Equal(t, "User ID 42 is Alice.", resp.Choices[0].Message.Content)
	assert.Equal(t, "3", resp.Metadata["goroute.orchestrator/loop_rounds"])
}

func TestToolLoopOrchestrator_MixedToolBatch(t *testing.T) {
	ctx := context.Background()
	idCtx := &domain.IdentityContext{OrgID: "org_test"}

	mcpHub := &mockMCPHubApp{
		tools: []domain.MCPTool{
			{Name: "mcp_file_read", IsActive: true},
		},
	}

	infApp := &mockInferenceApp{
		turns: []func(req *domain.CanonicalChatRequest) (*domain.CanonicalChatResponse, *router.ExecutionMeta, error){
			// Model calls BOTH an MCP tool (server-side) and a client-side function (client_action)
			func(req *domain.CanonicalChatRequest) (*domain.CanonicalChatResponse, *router.ExecutionMeta, error) {
				return &domain.CanonicalChatResponse{
					Choices: []domain.CanonicalChoice{
						{
							Index:        0,
							FinishReason: "tool_calls",
							Message: domain.CanonicalMessage{
								Role: "assistant",
								ToolCalls: []domain.CanonicalToolCall{
									{
										ID:   "call_mcp_1",
										Type: "function",
										Function: domain.CanonicalFunctionCall{
											Name:      "mcp_file_read",
											Arguments: `{"path": "/etc/hosts"}`,
										},
									},
									{
										ID:   "call_client_1",
										Type: "function",
										Function: domain.CanonicalFunctionCall{
											Name:      "client_custom_action",
											Arguments: `{"action": "prompt_user"}`,
										},
									},
								},
							},
						},
					},
					Usage: domain.TokenUsage{TotalTokens: 40},
				}, &router.ExecutionMeta{}, nil
			},
		},
	}

	orch := orchestrator.NewToolLoopOrchestrator(infApp, mcpHub, orchestrator.DefaultBudgetPolicy())

	chatReq := &domain.CanonicalChatRequest{
		Model: "gpt-4o",
		Messages: []domain.CanonicalMessage{
			{Role: "user", Content: "Read hosts and prompt user"},
		},
		Tools: []domain.CanonicalTool{
			{Type: "function", Function: domain.CanonicalFunction{Name: "mcp_file_read"}},
			{Type: "function", Function: domain.CanonicalFunction{Name: "client_custom_action"}},
		},
	}

	resp, _, err := orch.ExecuteLoop(ctx, idCtx, chatReq)
	require.NoError(t, err)

	// MCP tool was executed server-side
	require.Len(t, mcpHub.callLogs, 1)
	assert.Equal(t, "file_read", mcpHub.callLogs[0].ToolName)

	// Pending client-side call returned to client with finish_reason: "tool_calls"
	require.Len(t, resp.Choices[0].Message.ToolCalls, 1)
	assert.Equal(t, "client_custom_action", resp.Choices[0].Message.ToolCalls[0].Function.Name)
	assert.Equal(t, "tool_calls", resp.Choices[0].FinishReason)
}

func TestToolLoopOrchestrator_LookaheadStreaming(t *testing.T) {
	ctx := context.Background()
	idCtx := &domain.IdentityContext{OrgID: "org_test"}

	mcpHub := &mockMCPHubApp{
		tools: []domain.MCPTool{
			{Name: "calculator", IsActive: true},
		},
		callFuncs: map[string]func(input mcp.ToolCallInput) (*mcp.CallToolResponse, error){
			"calculator": func(input mcp.ToolCallInput) (*mcp.CallToolResponse, error) {
				return &mcp.CallToolResponse{
					Content: []mcp.ToolContent{
						{Type: "text", Text: "42"},
					},
				}, nil
			},
		},
	}

	infApp := &mockInferenceApp{
		turns: []func(req *domain.CanonicalChatRequest) (*domain.CanonicalChatResponse, *router.ExecutionMeta, error){
			// Turn 1: Model calls tool
			func(req *domain.CanonicalChatRequest) (*domain.CanonicalChatResponse, *router.ExecutionMeta, error) {
				return &domain.CanonicalChatResponse{
					ID:      "resp_stream_turn_1",
					Model:   "gpt-4o",
					Created: time.Now().Unix(),
					Choices: []domain.CanonicalChoice{
						{
							Index:        0,
							FinishReason: "tool_calls",
							Message: domain.CanonicalMessage{
								Role: "assistant",
								ToolCalls: []domain.CanonicalToolCall{
									{
										ID:   "call_calc",
										Type: "function",
										Function: domain.CanonicalFunctionCall{
											Name:      "calculator",
											Arguments: `{"expr": "6*7"}`,
										},
									},
								},
							},
						},
					},
					Usage: domain.TokenUsage{TotalTokens: 20},
				}, &router.ExecutionMeta{}, nil
			},
			// Turn 2: Model finishes with final answer
			func(req *domain.CanonicalChatRequest) (*domain.CanonicalChatResponse, *router.ExecutionMeta, error) {
				return &domain.CanonicalChatResponse{
					ID:      "resp_stream_turn_2",
					Model:   "gpt-4o",
					Created: time.Now().Unix(),
					Choices: []domain.CanonicalChoice{
						{
							Index:        0,
							FinishReason: "stop",
							Message: domain.CanonicalMessage{
								Role:    "assistant",
								Content: "The answer is 42.",
							},
						},
					},
					Usage: domain.TokenUsage{TotalTokens: 25},
				}, &router.ExecutionMeta{}, nil
			},
		},
	}

	orch := orchestrator.NewToolLoopOrchestrator(infApp, mcpHub, orchestrator.DefaultBudgetPolicy())

	chatReq := &domain.CanonicalChatRequest{
		Model:  "gpt-4o",
		Stream: true,
		Messages: []domain.CanonicalMessage{
			{Role: "user", Content: "Calculate 6*7"},
		},
		Tools: []domain.CanonicalTool{
			{Type: "function", Function: domain.CanonicalFunction{Name: "calculator"}},
		},
	}

	var chunks []*domain.CanonicalStreamChunk
	usage, _, err := orch.ExecuteStreamLoop(ctx, idCtx, chatReq, func(chunk *domain.CanonicalStreamChunk) error {
		chunks = append(chunks, chunk)
		return nil
	})

	require.NoError(t, err)
	assert.Equal(t, 45, usage.TotalTokens)

	// Verify streaming lookahead buffering:
	// ZERO chunks contained intermediate tool call tokens!
	var textParts []string
	for _, ch := range chunks {
		if ch.Choices[0].Delta.Content != "" {
			textParts = append(textParts, ch.Choices[0].Delta.Content)
		}
	}

	fullStreamedText := strings.TrimSpace(strings.Join(textParts, ""))
	assert.Equal(t, "The answer is 42.", fullStreamedText)

	// Verify last chunk has finish_reason: "stop"
	lastChunk := chunks[len(chunks)-1]
	require.NotNil(t, lastChunk.Choices[0].FinishReason)
	assert.Equal(t, "stop", *lastChunk.Choices[0].FinishReason)
}
