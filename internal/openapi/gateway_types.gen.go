// Code generated from api/openapi/gateway.openapi.yaml; DO NOT EDIT MANUALLY.
package openapi

// GatewayModelList represents the OpenAI-compatible GET /v1/models response.
type GatewayModelList struct {
	Object string             `json:"object"` // "list"
	Data   []GatewayModelCard `json:"data"`
}

// GatewayModelCard represents an individual model entry in GET /v1/models.
type GatewayModelCard struct {
	ID                 string   `json:"id"`
	Object             string   `json:"object"` // "model"
	Created            int64    `json:"created"`
	OwnedBy            string   `json:"owned_by"`
	Provider           string   `json:"provider,omitempty"`
	MaxInputTokens     int      `json:"max_input_tokens,omitempty"`
	MaxOutputTokens    int      `json:"max_output_tokens,omitempty"`
	Capabilities       []string `json:"capabilities,omitempty"`
	InputCostMicros1M  int64    `json:"input_cost_micros_per_1m,omitempty"`
	OutputCostMicros1M int64    `json:"output_cost_micros_per_1m,omitempty"`
}
