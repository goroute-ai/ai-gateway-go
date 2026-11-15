package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEnforceRoutingHintPolicies_PriorityFloorAndHeaders(t *testing.T) {
	cfg := config.Default()
	cfg.Router.AllowStrategyOverride = false
	srv := &GatewayServer{cfg: cfg}

	idLow := &domain.IdentityContext{
		KeyMinPriorityRank:  5,
		TeamMinPriorityRank: 8,
	}

	// Omitted priority header still clamps up to Team/Key floor (8).
	reqOmit := &domain.CanonicalChatRequest{Model: "m"}
	rOmit := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
	rOmit.Header.Set("X-Gateway-Routing-Strategy", "lowest_latency")
	rOmit.Header.Set("X-Gateway-Drop-Params", "true")
	require.Nil(t, srv.applyChatRoutingHints(rOmit, idLow, reqOmit))
	require.NotNil(t, reqOmit.GoRouteExtensions)
	assert.Equal(t, 8, reqOmit.GoRouteExtensions.Priority)
	assert.Empty(t, reqOmit.GoRouteExtensions.RoutingStrategy, "strategy override stripped when disabled")
	require.NotNil(t, reqOmit.GoRouteExtensions.DropUnsupportedParams)
	assert.True(t, *reqOmit.GoRouteExtensions.DropUnsupportedParams)

	// Negative / below-floor priority clamped up to floor (8).
	reqSpoof := &domain.CanonicalChatRequest{
		Model:             "m",
		GoRouteExtensions: &domain.GoRouteExtensions{Priority: -5},
	}
	require.Nil(t, srv.applyChatRoutingHints(httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil), idLow, reqSpoof))
	assert.Equal(t, 8, reqSpoof.GoRouteExtensions.Priority)

	// Explicitly lower priority rank (15 > 8) is preserved.
	reqLower := &domain.CanonicalChatRequest{
		Model:             "m",
		GoRouteExtensions: &domain.GoRouteExtensions{Priority: 15},
	}
	require.Nil(t, srv.applyChatRoutingHints(httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil), idLow, reqLower))
	assert.Equal(t, 15, reqLower.GoRouteExtensions.Priority)

	// Strategy override validated when enabled.
	cfg.Router.AllowStrategyOverride = true
	reqBadStrat := &domain.CanonicalChatRequest{Model: "m"}
	rBadStrat := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
	rBadStrat.Header.Set("X-Gateway-Routing-Strategy", "made_up_strategy")
	gwErr := srv.applyChatRoutingHints(rBadStrat, idLow, reqBadStrat)
	require.NotNil(t, gwErr)
	assert.Equal(t, http.StatusBadRequest, gwErr.StatusCode)
	assert.Equal(t, "invalid_routing_strategy", gwErr.Code)

	reqGoodStrat := &domain.CanonicalChatRequest{Model: "m"}
	rGoodStrat := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
	rGoodStrat.Header.Set("X-Gateway-Routing-Strategy", "LATENCY-BASED")
	require.Nil(t, srv.applyChatRoutingHints(rGoodStrat, idLow, reqGoodStrat))
	assert.Equal(t, "latency-based", reqGoodStrat.GoRouteExtensions.RoutingStrategy)

	// Strategy alias normalization accepts canonical aliases (weighted_shuffle, round_robin, simple-shuffle, priority-tiered).
	for rawAlias, wantNormalized := range map[string]string{
		"weighted_shuffle": "weighted-shuffle",
		"round_robin":      "round-robin",
		"simple-shuffle":   "weighted-shuffle",
		"priority-tiered":  "weighted-shuffle",
	} {
		reqAlias := &domain.CanonicalChatRequest{Model: "m"}
		rAlias := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
		rAlias.Header.Set("X-Gateway-Routing-Strategy", rawAlias)
		require.Nil(t, srv.applyChatRoutingHints(rAlias, idLow, reqAlias))
		assert.Equal(t, wantNormalized, reqAlias.GoRouteExtensions.RoutingStrategy)
	}
}
