package orchestrator

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/adapter"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/guardrails"
	"github.com/goroute-ai/ai-gateway-go/internal/guardrails/drivers"
	"github.com/goroute-ai/ai-gateway-go/internal/mcp"
	"github.com/goroute-ai/ai-gateway-go/internal/router"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
)

// InferenceApplication abstracts the inference engine for executing chat completions.
type InferenceApplication interface {
	ExecuteChat(ctx context.Context, idCtx *domain.IdentityContext, req *domain.CanonicalChatRequest) (*domain.CanonicalChatResponse, *router.ExecutionMeta, error)
	ExecuteStream(ctx context.Context, idCtx *domain.IdentityContext, req *domain.CanonicalChatRequest, onChunk adapter.StreamChunkHandler, onSelected func(dep *domain.Deployment)) (*domain.TokenUsage, *router.ExecutionMeta, error)
}

// MCPHubApplication abstracts the MCP Hub for tool discovery and execution.
type MCPHubApplication interface {
	ListTools(ctx context.Context, idCtx *domain.IdentityContext, serverSlug string) ([]domain.MCPTool, error)
	CallTool(ctx context.Context, idCtx *domain.IdentityContext, input mcp.ToolCallInput, meta mcp.CallMetadata) (*mcp.CallToolResponse, error)
}

// ExecutionBudgetPolicy defines bounds for the server-side tool orchestration loop.
type ExecutionBudgetPolicy struct {
	MaxLoopRounds      int           `json:"max_loop_rounds"`       // default: 5
	CumulativeTimeout  time.Duration `json:"cumulative_timeout"`    // e.g. 60s
	PerToolTimeout     time.Duration `json:"per_tool_timeout"`      // default: 10s
	MaxToolOutputBytes int64         `json:"max_tool_output_bytes"` // default: 512KB (524288)
	MaxSpendMicros     int64         `json:"max_spend_micros"`      // 0 = unlimited
}

// DefaultBudgetPolicy returns production-safe defaults for execution budgets.
func DefaultBudgetPolicy() ExecutionBudgetPolicy {
	return ExecutionBudgetPolicy{
		MaxLoopRounds:      5,
		CumulativeTimeout:  60 * time.Second,
		PerToolTimeout:     10 * time.Second,
		MaxToolOutputBytes: 512 * 1024, // 512KB
		MaxSpendMicros:     0,
	}
}

// ToolLoopOrchestrator coordinates multi-turn model tool execution server-side.
type ToolLoopOrchestrator struct {
	inferenceApp   InferenceApplication
	mcpHub         MCPHubApplication
	budget         ExecutionBudgetPolicy
	toolGuardrails []guardrails.Driver
	toolPolicyRepo storage.ToolPolicyRepository
}

// SetToolGuardrails attaches optional guardrail drivers (such as tool_permission and
// tool_policy) to enforce before tool dispatch and across multi-turn iterations.
func (o *ToolLoopOrchestrator) SetToolGuardrails(drvs ...guardrails.Driver) {
	if o == nil {
		return
	}
	filtered := make([]guardrails.Driver, 0, len(drvs))
	for _, d := range drvs {
		if d != nil {
			filtered = append(filtered, d)
		}
	}
	o.toolGuardrails = filtered
}

// SetToolPolicyRepository attaches an optional ToolPolicyRepository for tool trust-chain
// taint tracking when a dedicated ToolPolicyDriver has not already been registered.
func (o *ToolLoopOrchestrator) SetToolPolicyRepository(repo storage.ToolPolicyRepository) {
	if o == nil {
		return
	}
	o.toolPolicyRepo = repo
}

// NewToolLoopOrchestrator creates a new ToolLoopOrchestrator.
func NewToolLoopOrchestrator(
	inferenceApp InferenceApplication,
	mcpHub MCPHubApplication,
	budget ExecutionBudgetPolicy,
) *ToolLoopOrchestrator {
	if budget.MaxLoopRounds <= 0 {
		budget.MaxLoopRounds = 5
	}
	if budget.PerToolTimeout <= 0 {
		budget.PerToolTimeout = 10 * time.Second
	}
	if budget.MaxToolOutputBytes <= 0 {
		budget.MaxToolOutputBytes = 512 * 1024
	}
	return &ToolLoopOrchestrator{
		inferenceApp: inferenceApp,
		mcpHub:       mcpHub,
		budget:       budget,
	}
}

// ExecuteLoop runs the server-side multi-turn tool calling loop for non-streaming requests.
func (o *ToolLoopOrchestrator) ExecuteLoop(
	ctx context.Context,
	idCtx *domain.IdentityContext,
	req *domain.CanonicalChatRequest,
) (*domain.CanonicalChatResponse, *router.ExecutionMeta, error) {
	if o.budget.CumulativeTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, o.budget.CumulativeTimeout)
		defer cancel()
	}

	currMessages := make([]domain.CanonicalMessage, len(req.Messages))
	copy(currMessages, req.Messages)

	activeDrivers, policyDriver, err := o.resolveGovernanceDrivers()
	if err != nil {
		return nil, nil, err
	}
	var executedUntrustedTools []string

	if len(activeDrivers) > 0 {
		if err := evaluateRequestGovernance(ctx, activeDrivers, idCtx, req, currMessages, executedUntrustedTools); err != nil {
			return nil, nil, err
		}
	}

	// Fetch authorized MCP tools for caller to detect server-side eligible tools
	mcpToolMap := make(map[string]bool)
	if o.mcpHub != nil {
		if tools, err := o.mcpHub.ListTools(ctx, idCtx, ""); err == nil {
			for _, t := range tools {
				mcpToolMap[t.Name] = true
			}
		}
	}

	round := 0
	totalToolCalls := 0
	selfCorrectionAttempts := make(map[string]int)
	accumulatedUsage := domain.TokenUsage{}
	var lastMeta *router.ExecutionMeta
	var lastResp *domain.CanonicalChatResponse

	for round < o.budget.MaxLoopRounds {
		round++

		turnReq := *req
		turnReq.Messages = currMessages
		turnReq.Stream = false

		resp, meta, err := o.inferenceApp.ExecuteChat(ctx, idCtx, &turnReq)
		if err != nil {
			return nil, meta, err
		}
		lastMeta = meta
		lastResp = resp

		// Accumulate token usage (exact-once billing boundary)
		accumulatedUsage.PromptTokens += resp.Usage.PromptTokens
		accumulatedUsage.CompletionTokens += resp.Usage.CompletionTokens
		accumulatedUsage.TotalTokens += resp.Usage.TotalTokens

		if len(resp.Choices) == 0 {
			resp.Usage = accumulatedUsage
			return resp, meta, nil
		}

		choice := resp.Choices[0]
		if len(choice.Message.ToolCalls) == 0 {
			// Pure text completion without tool calls: loop finished
			resp.Usage = accumulatedUsage
			if resp.Metadata == nil {
				resp.Metadata = make(map[string]string)
			}
			resp.Metadata["goroute.orchestrator/loop_rounds"] = fmt.Sprint(round)
			resp.Metadata["goroute.orchestrator/total_tool_calls"] = fmt.Sprint(totalToolCalls)
			return resp, meta, nil
		}

		// Partition tool calls: server-side MCP tools vs client-side functions
		var serverSideCalls []domain.CanonicalToolCall
		var clientSideCalls []domain.CanonicalToolCall

		for _, tc := range choice.Message.ToolCalls {
			toolName := tc.Function.Name
			cleanName := strings.TrimPrefix(toolName, "mcp__")
			cleanName = strings.TrimPrefix(cleanName, "mcp_")

			if mcpToolMap[toolName] || mcpToolMap[cleanName] || strings.HasPrefix(toolName, "mcp_") || strings.HasPrefix(toolName, "mcp__") {
				serverSideCalls = append(serverSideCalls, tc)
			} else {
				clientSideCalls = append(clientSideCalls, tc)
			}
		}

		// If no tool calls in this batch are MCP tools, validate client-side calls and return to client
		if len(serverSideCalls) == 0 {
			if len(activeDrivers) > 0 {
				filteredClient, govErr := evaluateToolCallBatchGovernance(ctx, activeDrivers, idCtx, req, currMessages, clientSideCalls, executedUntrustedTools)
				if govErr != nil {
					return nil, meta, govErr
				}
				resp.Choices[0].Message.ToolCalls = filteredClient
				if len(filteredClient) == 0 && resp.Choices[0].FinishReason == "tool_calls" {
					resp.Choices[0].FinishReason = "stop"
				}
			}
			resp.Usage = accumulatedUsage
			return resp, meta, nil
		}

		// Append model's assistant turn with all requested tool calls
		assistantMsgIdx := len(currMessages)
		currMessages = append(currMessages, choice.Message)

		// Execute server-side MCP tools
		for _, tc := range serverSideCalls {
			totalToolCalls++
			toolName := tc.Function.Name
			cleanName := strings.TrimPrefix(toolName, "mcp__")
			cleanName = strings.TrimPrefix(cleanName, "mcp_")

			if len(activeDrivers) > 0 {
				evalHistory := buildToolGovernanceHistory(currMessages, assistantMsgIdx)
				checkedTC, allowed, govErr := evaluateSingleToolCallGovernance(ctx, activeDrivers, idCtx, req, evalHistory, tc, cleanName, executedUntrustedTools)
				if govErr != nil {
					return nil, meta, govErr
				}
				if !allowed {
					currMessages = append(currMessages, domain.CanonicalMessage{
						Role:       "tool",
						ToolCallID: tc.ID,
						Name:       toolName,
						Content:    fmt.Sprintf("{\"error\": \"Tool call %s removed by tool governance policy\"}", toolName),
					})
					continue
				}
				tc = checkedTC
				toolName = tc.Function.Name
				cleanName = strings.TrimPrefix(toolName, "mcp__")
				cleanName = strings.TrimPrefix(cleanName, "mcp_")
			}

			// Validate JSON arguments
			var argsMap map[string]any
			jsonErr := json.Unmarshal([]byte(tc.Function.Arguments), &argsMap)
			if jsonErr != nil {
				// Requirement 5: Self-Correcting JSON Recovery
				attempts := selfCorrectionAttempts[toolName]
				selfCorrectionAttempts[toolName] = attempts + 1
				if attempts == 0 {
					currMessages = append(currMessages, domain.CanonicalMessage{
						Role:       "tool",
						ToolCallID: tc.ID,
						Name:       toolName,
						Content:    fmt.Sprintf("{\"error\": \"Invalid JSON arguments for tool %s: %v. Please format arguments as valid JSON.\"}", toolName, jsonErr),
					})
					continue
				}
				currMessages = append(currMessages, domain.CanonicalMessage{
					Role:       "tool",
					ToolCallID: tc.ID,
					Name:       toolName,
					Content:    fmt.Sprintf("{\"error\": \"JSON parsing persistently failed for tool %s: %v\"}", toolName, jsonErr),
				})
				continue
			}

			// Execute tool via MCP Hub with per-tool timeout
			toolCtx := ctx
			var cancelTool context.CancelFunc
			if o.budget.PerToolTimeout > 0 {
				toolCtx, cancelTool = context.WithTimeout(ctx, o.budget.PerToolTimeout)
			}

			callInput := mcp.ToolCallInput{
				ToolName:  cleanName,
				Arguments: argsMap,
			}
			callMeta := mcp.CallMetadata{
				ProtocolVersion: domain.MCPProtocolVersion2026,
				RequestID:       req.RequestID,
			}

			toolResp, callErr := o.mcpHub.CallTool(toolCtx, idCtx, callInput, callMeta)
			if cancelTool != nil {
				cancelTool()
			}

			var resultText string
			if callErr != nil {
				resultText = fmt.Sprintf("{\"error\": %q}", callErr.Error())
			} else {
				var parts []string
				for _, c := range toolResp.Content {
					if c.Text != "" {
						parts = append(parts, c.Text)
					}
				}
				if len(parts) > 0 {
					resultText = strings.Join(parts, "\n")
				} else {
					resBytes, _ := json.Marshal(toolResp)
					resultText = string(resBytes)
				}
			}

			// Enforce max tool output size cap
			if o.budget.MaxToolOutputBytes > 0 && int64(len(resultText)) > o.budget.MaxToolOutputBytes {
				resultText = resultText[:o.budget.MaxToolOutputBytes] + "\n[Tool output truncated: exceeds 512KB limit]"
			}

			currMessages = append(currMessages, domain.CanonicalMessage{
				Role:       "tool",
				ToolCallID: tc.ID,
				Name:       toolName,
				Content:    resultText,
			})

			// Propagate executed tool taint across multi-hop agentic iterations.
			if policyDriver != nil {
				orgID, teamID, vkID := extractTenantScope(idCtx)
				if outPol, polErr := policyDriver.OutputPolicyForTool(ctx, orgID, teamID, vkID, toolName); polErr == nil && outPol == storage.ToolTrustUntrusted {
					if !slices.Contains(executedUntrustedTools, toolName) {
						executedUntrustedTools = append(executedUntrustedTools, toolName)
					}
				}
			}
		}

		// Requirement 4: If mixed batch had remaining client-side calls, validate and return them to client
		if len(clientSideCalls) > 0 {
			if len(activeDrivers) > 0 {
				filteredClient, govErr := evaluateToolCallBatchGovernance(ctx, activeDrivers, idCtx, req, currMessages, clientSideCalls, executedUntrustedTools)
				if govErr != nil {
					return nil, meta, govErr
				}
				clientSideCalls = filteredClient
			}
			resp.Choices[0].Message.ToolCalls = clientSideCalls
			if len(clientSideCalls) > 0 {
				resp.Choices[0].FinishReason = "tool_calls"
			} else {
				resp.Choices[0].FinishReason = "stop"
			}
			resp.Usage = accumulatedUsage
			return resp, meta, nil
		}
	}

	if lastResp != nil {
		lastResp.Usage = accumulatedUsage
		if lastResp.Metadata == nil {
			lastResp.Metadata = make(map[string]string)
		}
		lastResp.Metadata["goroute.orchestrator/loop_rounds"] = fmt.Sprint(round)
		lastResp.Metadata["goroute.orchestrator/total_tool_calls"] = fmt.Sprint(totalToolCalls)
		lastResp.Metadata["goroute.orchestrator/budget_exhausted"] = "true"
	}
	return lastResp, lastMeta, nil
}

// ExecuteStreamLoop executes the server-side tool orchestration loop with lookahead buffering for streaming.
// Intermediate tool turns are withheld from the client SSE stream; only the final completion is streamed.
func (o *ToolLoopOrchestrator) ExecuteStreamLoop(
	ctx context.Context,
	idCtx *domain.IdentityContext,
	req *domain.CanonicalChatRequest,
	onChunk adapter.StreamChunkHandler,
	onSelected func(dep *domain.Deployment),
) (*domain.TokenUsage, *router.ExecutionMeta, error) {
	// Execute the multi-turn loop with lookahead buffering
	resp, meta, err := o.ExecuteLoop(ctx, idCtx, req)
	if err != nil {
		return nil, meta, err
	}
	if meta != nil && meta.WinningDeployment != nil && onSelected != nil {
		onSelected(meta.WinningDeployment)
	}
	if resp == nil || len(resp.Choices) == 0 {
		return &domain.TokenUsage{}, meta, nil
	}

	choice := resp.Choices[0]
	content := choice.Message.Content

	// If final turn has tool calls (e.g. client-side unexecuted tool calls), emit them
	if len(choice.Message.ToolCalls) > 0 {
		reason := "tool_calls"
		chunk := &domain.CanonicalStreamChunk{
			ID:      resp.ID,
			Object:  "chat.completion.chunk",
			Created: resp.Created,
			Model:   resp.Model,
			Choices: []domain.CanonicalStreamChoice{
				{
					Index:        0,
					FinishReason: &reason,
					Delta: domain.CanonicalStreamDelta{
						Role:      "assistant",
						ToolCalls: choice.Message.ToolCalls,
					},
				},
			},
		}
		_ = onChunk(chunk)
		return &resp.Usage, meta, nil
	}

	// Stream final pure-text completion word-by-word
	words := strings.Fields(content)
	if len(words) == 0 && content != "" {
		words = []string{content}
	}

	for i, word := range words {
		delta := word
		if i > 0 {
			delta = " " + word
		}
		chunk := &domain.CanonicalStreamChunk{
			ID:      resp.ID,
			Object:  "chat.completion.chunk",
			Created: resp.Created,
			Model:   resp.Model,
			Choices: []domain.CanonicalStreamChoice{
				{
					Index:        0,
					FinishReason: nil,
					Delta: domain.CanonicalStreamDelta{
						Role:    "assistant",
						Content: delta,
					},
				},
			},
		}
		if err := onChunk(chunk); err != nil {
			return &resp.Usage, meta, err
		}
	}

	// Emit final stop chunk
	stopReason := "stop"
	stopChunk := &domain.CanonicalStreamChunk{
		ID:      resp.ID,
		Object:  "chat.completion.chunk",
		Created: resp.Created,
		Model:   resp.Model,
		Choices: []domain.CanonicalStreamChoice{
			{
				Index:        0,
				FinishReason: &stopReason,
				Delta:        domain.CanonicalStreamDelta{},
			},
		},
		Usage: &resp.Usage,
	}
	_ = onChunk(stopChunk)

	return &resp.Usage, meta, nil
}

func (o *ToolLoopOrchestrator) resolveGovernanceDrivers() ([]guardrails.Driver, *drivers.ToolPolicyDriver, error) {
	if len(o.toolGuardrails) == 0 && o.toolPolicyRepo == nil {
		return nil, nil, nil
	}
	active := make([]guardrails.Driver, 0, len(o.toolGuardrails)+1)
	var policyDrv *drivers.ToolPolicyDriver
	for _, d := range o.toolGuardrails {
		if d == nil {
			continue
		}
		active = append(active, d)
		if pd, ok := d.(*drivers.ToolPolicyDriver); ok && policyDrv == nil {
			policyDrv = pd
		}
	}
	if policyDrv == nil && o.toolPolicyRepo != nil {
		pd, err := drivers.NewToolPolicyDriver(guardrails.DriverConfig{}, o.toolPolicyRepo)
		if err != nil {
			return nil, nil, err
		}
		policyDrv = pd
		active = append(active, pd)
	}
	return active, policyDrv, nil
}

func buildToolGovernanceHistory(currMessages []domain.CanonicalMessage, assistantMsgIdx int) []domain.CanonicalMessage {
	if assistantMsgIdx < 0 || assistantMsgIdx >= len(currMessages) {
		return currMessages
	}
	respondedIDs := make(map[string]bool)
	for i := assistantMsgIdx + 1; i < len(currMessages); i++ {
		if strings.EqualFold(currMessages[i].Role, "tool") && currMessages[i].ToolCallID != "" {
			respondedIDs[currMessages[i].ToolCallID] = true
		}
	}
	history := make([]domain.CanonicalMessage, 0, len(currMessages))
	history = append(history, currMessages[:assistantMsgIdx]...)
	assistantMsg := currMessages[assistantMsgIdx]
	var completedCalls []domain.CanonicalToolCall
	for _, tc := range assistantMsg.ToolCalls {
		if tc.ID != "" && respondedIDs[tc.ID] {
			completedCalls = append(completedCalls, tc)
		}
	}
	if len(completedCalls) > 0 {
		assistantCopy := assistantMsg
		assistantCopy.ToolCalls = completedCalls
		history = append(history, assistantCopy)
	}
	history = append(history, currMessages[assistantMsgIdx+1:]...)
	return history
}

func extractTenantScope(idCtx *domain.IdentityContext) (orgID, teamID, virtualKeyID string) {
	if idCtx == nil {
		return "", "", ""
	}
	return idCtx.OrgID, idCtx.TeamID, idCtx.VirtualKeyID
}

func buildBaseEvalInput(
	hook domain.GuardrailHook,
	idCtx *domain.IdentityContext,
	req *domain.CanonicalChatRequest,
	messages []domain.CanonicalMessage,
	executedUntrustedTools []string,
) *domain.GuardrailEvalInput {
	orgID, teamID, vkID := extractTenantScope(idCtx)
	var userID string
	if idCtx != nil {
		userID = idCtx.UserID
	}
	meta := make(map[string]any)
	if req != nil && req.ToolChoice != nil {
		meta["tool_choice"] = req.ToolChoice
	}
	if len(executedUntrustedTools) > 0 {
		meta[drivers.MetaExecutedUntrustedTool] = slices.Clone(executedUntrustedTools)
	}
	in := &domain.GuardrailEvalInput{
		Direction:          domain.GuardrailDirectionInput,
		Hook:               hook,
		OrgID:              orgID,
		TeamID:             teamID,
		VirtualKeyID:       vkID,
		EndUserID:          userID,
		StructuredMessages: messages,
		Metadata:           meta,
	}
	if req != nil {
		in.RequestID = req.RequestID
		in.Model = req.Model
		in.Tools = req.Tools
	}
	return in
}

func evaluateRequestGovernance(
	ctx context.Context,
	drvs []guardrails.Driver,
	idCtx *domain.IdentityContext,
	req *domain.CanonicalChatRequest,
	messages []domain.CanonicalMessage,
	executedUntrustedTools []string,
) error {
	evalIn := buildBaseEvalInput(domain.GuardrailHookPreCall, idCtx, req, messages, executedUntrustedTools)
	for _, drv := range drvs {
		res, err := drv.Evaluate(ctx, evalIn)
		if err != nil {
			return err
		}
		if res != nil && res.Decision == domain.GuardrailDecisionBlock {
			return guardrailBlockGatewayError(res)
		}
	}
	return nil
}

func evaluateSingleToolCallGovernance(
	ctx context.Context,
	drvs []guardrails.Driver,
	idCtx *domain.IdentityContext,
	req *domain.CanonicalChatRequest,
	messages []domain.CanonicalMessage,
	tc domain.CanonicalToolCall,
	cleanName string,
	executedUntrustedTools []string,
) (domain.CanonicalToolCall, bool, error) {
	current := tc
	for _, drv := range drvs {
		evalIn := buildBaseEvalInput(domain.GuardrailHookPreMCPCall, idCtx, req, messages, executedUntrustedTools)
		evalIn.Tools = nil
		evalIn.ToolCalls = []domain.CanonicalToolCall{current}
		evalIn.Metadata["tool_name"] = cleanName
		delete(evalIn.Metadata, "tool_choice")

		res, err := drv.Evaluate(ctx, evalIn)
		if err != nil {
			return current, false, err
		}
		if res == nil {
			continue
		}
		switch res.Decision {
		case domain.GuardrailDecisionBlock:
			return current, false, guardrailBlockGatewayError(res)
		case domain.GuardrailDecisionModify:
			if len(res.ModifiedToolCalls) == 0 {
				return current, false, nil
			}
			current = res.ModifiedToolCalls[0]
		}
	}
	return current, true, nil
}

func evaluateToolCallBatchGovernance(
	ctx context.Context,
	drvs []guardrails.Driver,
	idCtx *domain.IdentityContext,
	req *domain.CanonicalChatRequest,
	messages []domain.CanonicalMessage,
	batch []domain.CanonicalToolCall,
	executedUntrustedTools []string,
) ([]domain.CanonicalToolCall, error) {
	current := slices.Clone(batch)
	for _, drv := range drvs {
		evalIn := buildBaseEvalInput(domain.GuardrailHookPostCall, idCtx, req, messages, executedUntrustedTools)
		evalIn.Direction = domain.GuardrailDirectionOutput
		evalIn.Tools = nil
		evalIn.ToolCalls = current
		delete(evalIn.Metadata, "tool_choice")

		res, err := drv.Evaluate(ctx, evalIn)
		if err != nil {
			return nil, err
		}
		if res == nil {
			continue
		}
		switch res.Decision {
		case domain.GuardrailDecisionBlock:
			return nil, guardrailBlockGatewayError(res)
		case domain.GuardrailDecisionModify:
			current = slices.Clone(res.ModifiedToolCalls)
		}
	}
	return current, nil
}

func guardrailBlockGatewayError(res *domain.GuardrailEvalResult) *domain.GatewayError {
	code := "guardrail_blocked"
	msg := "Tool invocation blocked by security guardrail"
	if res != nil {
		if res.ErrorMessage != "" {
			msg = res.ErrorMessage
		}
		for _, v := range res.Violations {
			if v.Category == drivers.CodeViolatedToolPolicy || v.Rule == drivers.CodeViolatedToolPolicy {
				code = drivers.CodeViolatedToolPolicy
				if res.ErrorMessage == "" && v.Message != "" {
					msg = v.Message
				}
				break
			}
			if res.ErrorMessage == "" && v.Message != "" {
				msg = v.Message
			}
		}
	}
	return &domain.GatewayError{
		StatusCode: http.StatusBadRequest,
		Type:       domain.ErrorTypeInvalidRequest,
		Code:       code,
		Message:    msg,
	}
}
