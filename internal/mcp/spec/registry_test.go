package spec_test

import (
	"testing"

	"github.com/goroute-ai/ai-gateway-go/internal/mcp/spec"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestSupportedSpecsAndCompiledSchemas(t *testing.T) {
	specs := spec.SupportedSpecs()
	require.Len(t, specs, 5)
	assert.Equal(t, []string{
		"2024-11-05",
		"2025-03-26",
		"2025-06-18",
		"2025-11-25",
		"2026-07-28",
	}, spec.SupportedVersions())
	assert.Equal(t, "2026-07-28", spec.DefaultVersion)

	require.NoError(t, spec.ValidateAllCompiled())

	for _, ver := range spec.SupportedVersions() {
		raw, err := spec.SchemaBytes(ver)
		require.NoError(t, err)
		require.NotEmpty(t, raw)
		var parsed map[string]any
		require.NoError(t, yaml.Unmarshal(raw, &parsed), "version %s must be valid YAML", ver)
	}

	s202503, ok := spec.GetSpec("2025-03-26")
	require.True(t, ok)
	assert.True(t, s202503.SupportsBatching)
	assert.False(t, s202503.RequiresProtocolVersionHeader)

	s202506, ok := spec.GetSpec("2025-06-18")
	require.True(t, ok)
	assert.False(t, s202506.SupportsBatching)
	assert.True(t, s202506.RequiresProtocolVersionHeader)
	assert.True(t, s202506.SupportsStructuredContent)

	s2026, ok := spec.GetSpec("2026-07-28")
	require.True(t, ok)
	assert.True(t, s2026.SupportsServerDiscover)
	assert.True(t, s2026.SupportsSubscriptionsPost)
	assert.False(t, s2026.SupportsSessions)
	assert.True(t, s2026.SupportsResultType)
}
