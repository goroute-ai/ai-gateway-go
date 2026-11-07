package gateway

// Message represents a single chat turn in a ChatRequest.
type Message struct {
	Role       string     `json:"role"` // "system", "user", "assistant", "tool"
	Content    string     `json:"content"`
	Name       string     `json:"name,omitempty"`
	ToolCallID string     `json:"tool_call_id,omitempty"`
	ToolCalls  []ToolCall `json:"tool_calls,omitempty"`
}

// ToolCall represents a tool invocation requested by the model.
type ToolCall struct {
	ID       string       `json:"id"`
	Type     string       `json:"type"` // "function"
	Function FunctionCall `json:"function"`
}

// FunctionCall contains the function name and JSON arguments string.
type FunctionCall struct {
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
}

// ChatRequest specifies input parameters for a multi-turn or customized chat completion.
type ChatRequest struct {
	Model           string    `json:"model"`
	Messages        []Message `json:"messages"`
	Temperature     *float64  `json:"temperature,omitempty"`
	TopP            *float64  `json:"top_p,omitempty"`
	MaxTokens       *int      `json:"max_tokens,omitempty"`
	Stop            []string  `json:"stop,omitempty"`
	Stream          bool      `json:"stream,omitempty"`
	ReasoningEffort string    `json:"reasoning_effort,omitempty"` // "low", "medium", "high"
	User            string    `json:"user,omitempty"`
}

// VirtualKeyRequest specifies parameters for issuing a new Gateway Virtual API Key.
type VirtualKeyRequest struct {
	Name            string   `json:"name"`
	OrgID           string   `json:"org_id,omitempty"`
	TeamID          string   `json:"team_id,omitempty"`
	UserID          string   `json:"user_id,omitempty"`
	Role            string   `json:"role,omitempty"` // "org_admin", "team_admin", "developer", "service_account"
	MaxBudgetMicros int64    `json:"max_budget_micros,omitempty"`
	RPMLimit        int      `json:"rpm_limit,omitempty"`
	TPMLimit        int      `json:"tpm_limit,omitempty"`
	AllowedModels   []string `json:"allowed_models,omitempty"`
}

// VirtualKeyInfo holds information about an issued virtual API key.
type VirtualKeyInfo struct {
	ID              string   `json:"id"`
	Key             string   `json:"key,omitempty"` // Raw token (RawKey), only visible upon creation
	KeyPrefix       string   `json:"key_prefix"`
	Name            string   `json:"name"`
	Role            string   `json:"role"`
	OrgID           string   `json:"org_id"`
	MaxBudgetMicros int64    `json:"max_budget_micros"`
	RPMLimit        int      `json:"rpm_limit"`
	TPMLimit        int      `json:"tpm_limit"`
	AllowedModels   []string `json:"allowed_models"`
	IsActive        bool     `json:"is_active"`
}

// MCPServerConfig specifies registration parameters for a Model Context Protocol tool server.
type MCPServerConfig struct {
	Name        string `json:"name"`
	Slug        string `json:"slug"`
	Description string `json:"description,omitempty"`
	Transport   string `json:"transport,omitempty"` // "streamable_http", "http-sse"
	URL         string `json:"url"`
	Enabled     bool   `json:"enabled"`
}

// A2AAgentConfig specifies registration parameters for an Agent-to-Agent protocol agent.
type A2AAgentConfig struct {
	Name        string `json:"name"`
	Slug        string `json:"slug"`
	Description string `json:"description,omitempty"`
	EndpointURL string `json:"endpoint_url"`
	Status      string `json:"status,omitempty"`
}

// SystemIdentity represents an authenticated system or service caller identity.
type SystemIdentity struct {
	OrgID  string `json:"org_id"`
	UserID string `json:"user_id,omitempty"`
	TeamID string `json:"team_id,omitempty"`
	Role   string `json:"role,omitempty"`
}
