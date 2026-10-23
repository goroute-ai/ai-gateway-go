package spec

import (
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"gopkg.in/yaml.v3"
)

//go:embed schemas/*/schema.yaml
var embeddedSchemas embed.FS

var (
	validatorCacheMu sync.Mutex
	validatorCache   = make(map[string]*jsonschema.Schema)
)

// SchemaBytes returns the raw embedded official schema.yaml bytes for version.
func SchemaBytes(version string) ([]byte, error) {
	if !IsSupported(version) {
		return nil, fmt.Errorf("unsupported mcp schema version %q", version)
	}
	raw, err := embeddedSchemas.ReadFile("schemas/" + version + "/schema.yaml")
	if err != nil {
		return nil, fmt.Errorf("read embedded schema %s: %w", version, err)
	}
	return raw, nil
}

// ValidateDefinition compiles (once per release/definition) and validates payloadJSON
// against `#/<defsKey>/<defName>` inside the official MCP schema for version.
func ValidateDefinition(version, defName string, payloadJSON []byte) error {
	s, err := compiledDefinitionSchema(version, defName)
	if err != nil {
		return err
	}
	v, err := jsonschema.UnmarshalJSON(bytes.NewReader(payloadJSON))
	if err != nil {
		return fmt.Errorf("invalid JSON payload: %w", err)
	}
	if err := s.Validate(v); err != nil {
		return fmt.Errorf("mcp %s schema validation (%s): %w", version, defName, err)
	}
	return nil
}

// ValidateAllCompiled compiles every definition root (`ClientRequest`) for version to confirm schema integrity.
func ValidateAllCompiled() error {
	for _, info := range generatedSpecs {
		if _, err := compiledDefinitionSchema(info.Version, "ClientRequest"); err != nil {
			return fmt.Errorf("compile %s: %w", info.Version, err)
		}
	}
	return nil
}

func compiledDefinitionSchema(version, defName string) (*jsonschema.Schema, error) {
	info, ok := GetSpec(version)
	if !ok {
		return nil, fmt.Errorf("unsupported mcp version %q", version)
	}

	cacheKey := version + "#" + defName
	validatorCacheMu.Lock()
	if existing, exists := validatorCache[cacheKey]; exists {
		validatorCacheMu.Unlock()
		return existing, nil
	}
	validatorCacheMu.Unlock()

	raw, err := SchemaBytes(version)
	if err != nil {
		return nil, err
	}

	var yamlDoc any
	if err := yaml.Unmarshal(raw, &yamlDoc); err != nil {
		return nil, fmt.Errorf("unmarshal embedded yaml schema %s: %w", version, err)
	}
	normalizedJSON, err := json.Marshal(yamlDoc)
	if err != nil {
		return nil, fmt.Errorf("normalize embedded yaml schema %s: %w", version, err)
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(normalizedJSON))
	if err != nil {
		return nil, fmt.Errorf("parse normalized schema %s: %w", version, err)
	}

	baseURI := "https://goroute.internal/mcp/" + version + "/schema.yaml"
	wrapperURI := "https://goroute.internal/mcp/" + version + "/wrap/" + defName + ".json"
	wrapperDoc := map[string]any{
		"$ref": baseURI + "#/" + info.defsKey + "/" + defName,
	}
	if info.SchemaDialect != "" {
		wrapperDoc["$schema"] = info.SchemaDialect
	}
	wrapperBytes, _ := json.Marshal(wrapperDoc)
	wrapperParsed, err := jsonschema.UnmarshalJSON(bytes.NewReader(wrapperBytes))
	if err != nil {
		return nil, fmt.Errorf("parse schema wrapper %s: %w", cacheKey, err)
	}

	compiler := jsonschema.NewCompiler()
	if err := compiler.AddResource(baseURI, doc); err != nil {
		return nil, fmt.Errorf("add schema resource %s: %w", version, err)
	}
	if err := compiler.AddResource(wrapperURI, wrapperParsed); err != nil {
		return nil, fmt.Errorf("add schema wrapper %s: %w", cacheKey, err)
	}

	compiled, err := compiler.Compile(wrapperURI)
	if err != nil {
		return nil, fmt.Errorf("compile schema %s: %w", cacheKey, err)
	}

	validatorCacheMu.Lock()
	validatorCache[cacheKey] = compiled
	validatorCacheMu.Unlock()
	return compiled, nil
}
