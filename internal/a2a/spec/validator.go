package a2aspec

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"maps"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"gopkg.in/yaml.v3"
)

//go:embed a2a.openapi.yaml
var embeddedOpenAPIYAML []byte

const (
	a2aSchemaBaseURI       = "https://goroute.internal/a2a/v1.0/openapi.yaml"
	a2aStrictSchemaBaseURI = "https://goroute.internal/a2a/v1.0/openapi-strict.yaml"
)

var (
	validatorMu         sync.Mutex
	validatorCache      = make(map[string]*jsonschema.Schema)
	schemaDocOnce       sync.Once
	schemaDocErr        error
	normalizedDoc       any
	normalizedStrictDoc any
	declaredSchemaNames []string
)

// OpenAPIYAML returns a copy of the embedded authoritative A2A v1.0 OpenAPI YAML bytes.
func OpenAPIYAML() []byte {
	return bytes.Clone(embeddedOpenAPIYAML)
}

func loadNormalizedDocs() error {
	schemaDocOnce.Do(func() {
		var yamlDoc any
		if err := yaml.Unmarshal(embeddedOpenAPIYAML, &yamlDoc); err != nil {
			schemaDocErr = fmt.Errorf("unmarshal embedded a2a.openapi.yaml: %w", err)
			return
		}
		rawJSON, err := json.Marshal(yamlDoc)
		if err != nil {
			schemaDocErr = fmt.Errorf("marshal normalized a2a openapi doc: %w", err)
			return
		}
		doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(rawJSON))
		if err != nil {
			schemaDocErr = fmt.Errorf("parse normalized a2a openapi doc: %w", err)
			return
		}
		normalizedDoc = doc

		// Extract declared component schema names for ValidateAllCompiled.
		if rootMap, ok := yamlDoc.(map[string]any); ok {
			if comps, ok := rootMap["components"].(map[string]any); ok {
				if schemas, ok := comps["schemas"].(map[string]any); ok {
					for name := range schemas {
						declaredSchemaNames = append(declaredSchemaNames, name)
					}
					for _, rawSchema := range schemas {
						enforceStrictAdditionalProperties(rawSchema)
					}
				}
			}
		}

		strictJSON, err := json.Marshal(yamlDoc)
		if err != nil {
			schemaDocErr = fmt.Errorf("marshal strict a2a openapi doc: %w", err)
			return
		}
		strictParsed, err := jsonschema.UnmarshalJSON(bytes.NewReader(strictJSON))
		if err != nil {
			schemaDocErr = fmt.Errorf("parse strict a2a openapi doc: %w", err)
			return
		}
		normalizedStrictDoc = strictParsed
	})
	return schemaDocErr
}

// enforceStrictAdditionalProperties sets additionalProperties=false on structured
// component object schemas that declare explicit properties without allowing arbitrary keys.
func enforceStrictAdditionalProperties(node any) {
	switch val := node.(type) {
	case map[string]any:
		if _, hasProps := val["properties"]; hasProps {
			if _, hasAdditional := val["additionalProperties"]; !hasAdditional {
				val["additionalProperties"] = false
			}
		}
		for _, child := range val {
			enforceStrictAdditionalProperties(child)
		}
	case []any:
		for _, item := range val {
			enforceStrictAdditionalProperties(item)
		}
	}
}

func compileComponentSchema(schemaName string, strict bool) (*jsonschema.Schema, error) {
	if err := loadNormalizedDocs(); err != nil {
		return nil, err
	}

	mode := "standard"
	baseURI := a2aSchemaBaseURI
	baseDoc := normalizedDoc
	if strict {
		mode = "strict"
		baseURI = a2aStrictSchemaBaseURI
		baseDoc = normalizedStrictDoc
	}

	cacheKey := mode + "#" + schemaName
	validatorMu.Lock()
	if existing, ok := validatorCache[cacheKey]; ok {
		validatorMu.Unlock()
		return existing, nil
	}
	validatorMu.Unlock()

	wrapperURI := fmt.Sprintf("https://goroute.internal/a2a/v1.0/%s/%s.json", mode, schemaName)
	wrapperBytes, err := json.Marshal(map[string]any{
		"$schema": "https://json-schema.org/draft/2020-12/schema",
		"$ref":    baseURI + "#/components/schemas/" + schemaName,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal wrapper for %s: %w", schemaName, err)
	}
	wrapperDoc, err := jsonschema.UnmarshalJSON(bytes.NewReader(wrapperBytes))
	if err != nil {
		return nil, fmt.Errorf("parse wrapper for %s: %w", schemaName, err)
	}

	compiler := jsonschema.NewCompiler()
	if err := compiler.AddResource(baseURI, baseDoc); err != nil {
		return nil, fmt.Errorf("add a2a openapi resource: %w", err)
	}
	if err := compiler.AddResource(wrapperURI, wrapperDoc); err != nil {
		return nil, fmt.Errorf("add wrapper resource %s: %w", cacheKey, err)
	}

	compiled, err := compiler.Compile(wrapperURI)
	if err != nil {
		return nil, fmt.Errorf("compile a2a schema %s: %w", cacheKey, err)
	}

	validatorMu.Lock()
	// Another goroutine may have compiled the same schema concurrently.
	if existing, ok := validatorCache[cacheKey]; ok {
		validatorMu.Unlock()
		return existing, nil
	}
	validatorCache[cacheKey] = compiled
	validatorMu.Unlock()
	return compiled, nil
}

// ValidateSchema validates payloadJSON against components.schemas.<schemaName>
// in the embedded A2A v1.0 OpenAPI 3.1.0 specification.
func ValidateSchema(schemaName string, payloadJSON []byte) error {
	return validatePayload(schemaName, payloadJSON, false)
}

// ValidateSchemaStrict validates payloadJSON against components.schemas.<schemaName>
// and rejects unknown fields on structured objects (preserving strict protobuf parity).
func ValidateSchemaStrict(schemaName string, payloadJSON []byte) error {
	return validatePayload(schemaName, payloadJSON, true)
}

func validatePayload(schemaName string, payloadJSON []byte, strict bool) error {
	if schemaName == "" {
		return fmt.Errorf("schema name is required")
	}
	compiled, err := compileComponentSchema(schemaName, strict)
	if err != nil {
		return err
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(payloadJSON))
	if err != nil {
		return fmt.Errorf("invalid JSON payload: %w", err)
	}
	if err := compiled.Validate(doc); err != nil {
		return fmt.Errorf("a2a openapi schema validation (%s): %w", schemaName, err)
	}
	return nil
}

// DecodeStrict validates payloadJSON strictly against schemaName (including oneOf,
// required fields, enums, and unknown-field rejection) and unmarshals it into T.
func DecodeStrict[T any](schemaName string, payloadJSON []byte) (*T, error) {
	if len(bytes.TrimSpace(payloadJSON)) == 0 {
		return nil, fmt.Errorf("empty JSON payload for %s", schemaName)
	}
	if err := ValidateSchemaStrict(schemaName, payloadJSON); err != nil {
		return nil, err
	}
	var out T
	if err := json.Unmarshal(payloadJSON, &out); err != nil {
		return nil, fmt.Errorf("decode %s: %w", schemaName, err)
	}
	return &out, nil
}

// ValidateAllCompiled compiles every schema in components.schemas to guarantee
// the embedded A2A v1.0 OpenAPI document contains zero invalid or dangling refs.
func ValidateAllCompiled() error {
	if err := loadNormalizedDocs(); err != nil {
		return err
	}
	if len(declaredSchemaNames) == 0 {
		return fmt.Errorf("embedded a2a.openapi.yaml contains zero component schemas")
	}
	names := make([]string, 0, len(declaredSchemaNames))
	names = append(names, declaredSchemaNames...)
	for _, name := range names {
		if _, err := compileComponentSchema(name, false); err != nil {
			return err
		}
		if _, err := compileComponentSchema(name, true); err != nil {
			return err
		}
	}
	return nil
}

// CloneMetadata returns a shallow-safe copy of an A2A Metadata map.
func CloneMetadata(src *Metadata) *Metadata {
	if src == nil {
		return nil
	}
	cp := make(Metadata, len(*src))
	maps.Copy(cp, *src)
	return &cp
}
