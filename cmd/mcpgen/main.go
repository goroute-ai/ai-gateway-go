// Command mcpgen generates strongly typed Go protocol packages, capability metadata,
// and embedded YAML Schema validators from vendored official MCP schemas under docs/specs/mcp/.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"go/format"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode"

	"gopkg.in/yaml.v3"
)

type schemaDoc struct {
	Schema      string         `json:"$schema"`
	Defs        map[string]any `json:"$defs"`
	Definitions map[string]any `json:"definitions"`
}

func (d schemaDoc) defsMap() (string, map[string]any) {
	if len(d.Defs) > 0 {
		return "$defs", d.Defs
	}
	return "definitions", d.Definitions
}

type releaseCapabilities struct {
	Version                    string
	PackageName                string
	SchemaDialect              string
	DefsKey                    string
	DefCount                   int
	Label                      string
	Summary                    string
	TransportMode              string
	DefaultTransport           string
	AllowedTransports          []string
	SupportsSessions           bool
	RequiresInitialize         bool
	SupportsBatching           bool
	RequiresProtocolVersionHdr bool
	RequiresMirroredHeaders    bool
	SupportsServerDiscover     bool
	SupportsSubscriptionsPost  bool
	SupportsTasks              bool
	SupportsStructuredContent  bool
	SupportsElicitation        bool
	SupportsResultType         bool
	ClientRequestMethods       []string
	ClientNotificationMethods  []string
	ServerNotificationMethods  []string
}

func main() {
	rootDir := flag.String("root", ".", "Repository root directory")
	flag.Parse()

	srcDir := filepath.Join(*rootDir, "docs", "specs", "mcp")
	outBase := filepath.Join(*rootDir, "internal", "mcp", "spec")
	embedDir := filepath.Join(outBase, "schemas")

	versions, err := discoverVersions(srcDir)
	if err != nil {
		fatal("discover mcp schema versions: %v", err)
	}
	if len(versions) == 0 {
		fatal("no mcp schema versions found in %s", srcDir)
	}

	var releases []releaseCapabilities
	for _, ver := range versions {
		srcPath := filepath.Join(srcDir, ver, "schema.yaml")
		raw, err := os.ReadFile(srcPath)
		if err != nil {
			fatal("read %s: %v", srcPath, err)
		}

		dstEmbedDir := filepath.Join(embedDir, ver)
		if err := os.MkdirAll(dstEmbedDir, 0o755); err != nil {
			fatal("mkdir %s: %v", dstEmbedDir, err)
		}
		if err := os.Remove(filepath.Join(dstEmbedDir, "schema.json")); err != nil && !os.IsNotExist(err) {
			fatal("remove legacy schema.json %s: %v", ver, err)
		}
		if err := os.WriteFile(filepath.Join(dstEmbedDir, "schema.yaml"), raw, 0o644); err != nil {
			fatal("copy embedded schema %s: %v", ver, err)
		}

		caps, err := processVersion(ver, raw, outBase)
		if err != nil {
			fatal("generate version %s: %v", ver, err)
		}
		releases = append(releases, caps)
		fmt.Printf("mcpgen: generated %s -> %s (%d definitions, %d client methods)\n",
			ver, caps.PackageName, caps.DefCount, len(caps.ClientRequestMethods))
	}

	if err := writeRegistry(outBase, releases); err != nil {
		fatal("write registry.gen.go: %v", err)
	}
	fmt.Printf("mcpgen: generated registry for %d releases in %s\n", len(releases), outBase)
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}

func discoverVersions(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read dir %s: %w", dir, err)
	}
	versions := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		schemaPath := filepath.Join(dir, e.Name(), "schema.yaml")
		if _, statErr := os.Stat(schemaPath); statErr == nil {
			versions = append(versions, e.Name())
		}
	}
	sort.Strings(versions)
	return versions, nil
}

func processVersion(ver string, raw []byte, outBase string) (releaseCapabilities, error) {
	var yamlTree any
	if err := yaml.Unmarshal(raw, &yamlTree); err != nil {
		return releaseCapabilities{}, fmt.Errorf("unmarshal schema.yaml: %w", err)
	}
	normalized, err := json.Marshal(yamlTree)
	if err != nil {
		return releaseCapabilities{}, fmt.Errorf("normalize schema.yaml: %w", err)
	}
	var doc schemaDoc
	if err := json.Unmarshal(normalized, &doc); err != nil {
		return releaseCapabilities{}, fmt.Errorf("decode normalized schema: %w", err)
	}
	defsKey, defs := doc.defsMap()
	if len(defs) == 0 {
		return releaseCapabilities{}, fmt.Errorf("schema %s contains no definitions", ver)
	}

	pkgName := "v" + strings.ReplaceAll(ver, "-", "")
	caps := extractCapabilities(ver, pkgName, doc.Schema, defsKey, defs)

	srcCode, err := generateVersionPackage(ver, pkgName, defs)
	if err != nil {
		return releaseCapabilities{}, err
	}

	pkgDir := filepath.Join(outBase, pkgName)
	if err := os.MkdirAll(pkgDir, 0o755); err != nil {
		return releaseCapabilities{}, fmt.Errorf("mkdir %s: %w", pkgDir, err)
	}
	outFile := filepath.Join(pkgDir, "types.gen.go")
	if err := os.WriteFile(outFile, srcCode, 0o644); err != nil {
		return releaseCapabilities{}, fmt.Errorf("write %s: %w", outFile, err)
	}
	return caps, nil
}

func extractCapabilities(
	ver string,
	pkgName string,
	dialect string,
	defsKey string,
	defs map[string]any,
) releaseCapabilities {
	clientReqMethods := extractUnionMethodConsts(defs, "ClientRequest")
	clientNotifMethods := extractUnionMethodConsts(defs, "ClientNotification")
	serverNotifMethods := extractUnionMethodConsts(defs, "ServerNotification")

	hasBatch := hasDef(defs, "JSONRPCBatchRequest")
	hasDiscover := hasString(clientReqMethods, "server/discover")
	hasInitialize := hasString(clientReqMethods, "initialize")
	hasSubscriptionsListen := hasString(clientReqMethods, "subscriptions/listen")
	hasTasks := hasString(clientReqMethods, "tasks/get") || hasString(clientReqMethods, "tasks/list")
	hasStructured := hasProp(defs, "CallToolResult", "structuredContent")
	hasElicitation := hasDef(defs, "ElicitRequest")
	hasResultType := hasProp(defs, "Result", "resultType")
	hasHeaderMismatch := hasDef(defs, "HeaderMismatchError")

	isHTTP2024 := ver == "2024-11-05"
	isStatefulHTTP := !isHTTP2024 && !hasDiscover
	isStateless := hasDiscover

	transportMode := "stateless_streamable_http"
	defaultTransport := "streamable_http"
	allowedTransports := []string{"streamable_http", "stdio", "openapi"}
	switch {
	case isHTTP2024:
		transportMode = "http_sse_2024"
		defaultTransport = "http_sse_2024"
		allowedTransports = []string{"http_sse_2024", "stdio", "openapi"}
	case isStatefulHTTP:
		transportMode = "stateful_streamable_http"
	}

	label, summary := describeRelease(ver)

	return releaseCapabilities{
		Version:                    ver,
		PackageName:                pkgName,
		SchemaDialect:              dialect,
		DefsKey:                    defsKey,
		DefCount:                   len(defs),
		Label:                      label,
		Summary:                    summary,
		TransportMode:              transportMode,
		DefaultTransport:           defaultTransport,
		AllowedTransports:          allowedTransports,
		SupportsSessions:           isHTTP2024 || isStatefulHTTP,
		RequiresInitialize:         hasInitialize,
		SupportsBatching:           hasBatch,
		RequiresProtocolVersionHdr: ver == "2025-06-18" || ver == "2025-11-25" || isStateless,
		RequiresMirroredHeaders:    hasHeaderMismatch,
		SupportsServerDiscover:     hasDiscover,
		SupportsSubscriptionsPost:  hasSubscriptionsListen,
		SupportsTasks:              hasTasks,
		SupportsStructuredContent:  hasStructured,
		SupportsElicitation:        hasElicitation,
		SupportsResultType:         hasResultType,
		ClientRequestMethods:       clientReqMethods,
		ClientNotificationMethods:  clientNotifMethods,
		ServerNotificationMethods:  serverNotifMethods,
	}
}

func describeRelease(ver string) (string, string) {
	switch ver {
	case "2024-11-05":
		return "2024-11-05 (Initial HTTP+SSE)",
			"Initial stable MCP specification with HTTP+SSE transport (GET /sse + POST /message), initialize handshake, and stdio."
	case "2025-03-26":
		return "2025-03-26 (Streamable HTTP + Batching)",
			"Introduced Streamable HTTP with Mcp-Session-Id, OAuth 2.1 authorization, JSON-RPC batching, and tool annotations."
	case "2025-06-18":
		return "2025-06-18 (Structured Output + Elicitation)",
			"Removed JSON-RPC batching, added structuredContent, resource_link, elicitation, and mandatory MCP-Protocol-Version header."
	case "2025-11-25":
		return "2025-11-25 (Tasks, Icons & CIMD)",
			"Added Tasks lifecycle, icons metadata, CIMD/OIDC discovery, URL elicitation, and sampling tool calling."
	case "2026-07-28":
		return "2026-07-28 (Stateless Core — Latest)",
			"Stateless Streamable HTTP with server/discover, Mcp-Method/Mcp-Name mirrored headers, POST subscriptions/listen SSE, MRTR input_required, and cacheable results."
	default:
		return ver, fmt.Sprintf("MCP specification release %s generated from official schema.yaml.", ver)
	}
}

func extractUnionMethodConsts(defs map[string]any, unionName string) []string {
	raw, ok := defs[unionName].(map[string]any)
	if !ok {
		return []string{}
	}
	methods := make([]string, 0)
	seen := make(map[string]struct{})

	collectFromDef := func(m map[string]any) {
		props, _ := m["properties"].(map[string]any)
		methodSchema, _ := props["method"].(map[string]any)
		if c, ok := methodSchema["const"].(string); ok && c != "" {
			if _, exists := seen[c]; !exists {
				seen[c] = struct{}{}
				methods = append(methods, c)
			}
		}
	}

	collectFromDef(raw)
	if anyOf, ok := raw["anyOf"].([]any); ok {
		for _, item := range anyOf {
			itemMap, ok := item.(map[string]any)
			if !ok {
				continue
			}
			if ref, ok := itemMap["$ref"].(string); ok {
				refName := refBaseName(ref)
				if target, exists := defs[refName].(map[string]any); exists {
					collectFromDef(target)
				}
			} else {
				collectFromDef(itemMap)
			}
		}
	}
	return methods
}

func refBaseName(ref string) string {
	idx := strings.LastIndex(ref, "/")
	if idx < 0 {
		return ref
	}
	return ref[idx+1:]
}

func hasDef(defs map[string]any, name string) bool {
	v, ok := defs[name]
	return ok && v != nil
}

func hasProp(defs map[string]any, defName, propName string) bool {
	defMap, ok := defs[defName].(map[string]any)
	if !ok {
		return false
	}
	props, ok := defMap["properties"].(map[string]any)
	if !ok {
		return false
	}
	_, exists := props[propName]
	return exists
}

func hasString(items []string, target string) bool {
	for _, it := range items {
		if it == target {
			return true
		}
	}
	return false
}

func generateVersionPackage(ver, pkgName string, defs map[string]any) ([]byte, error) {
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "// Code generated by cmd/mcpgen from docs/specs/mcp/%s/schema.yaml. DO NOT EDIT.\n\n", ver)
	fmt.Fprintf(&buf, "package %s\n\n", pkgName)

	fmt.Fprintf(&buf, "// ProtocolVersion is the official MCP specification release date.\n")
	fmt.Fprintf(&buf, "const ProtocolVersion = %q\n\n", ver)

	writeStringSliceVar(&buf, "ClientRequestMethods", extractUnionMethodConsts(defs, "ClientRequest"))
	writeStringSliceVar(&buf, "ClientNotificationMethods", extractUnionMethodConsts(defs, "ClientNotification"))
	writeStringSliceVar(&buf, "ServerNotificationMethods", extractUnionMethodConsts(defs, "ServerNotification"))

	names := make([]string, 0, len(defs))
	for name := range defs {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		defMap, ok := defs[name].(map[string]any)
		if !ok || defMap == nil {
			continue
		}
		goName := exportIdent(name)
		if goName == "" {
			continue
		}
		props := mergedProperties(defMap, defs)
		reqSet := mergedRequired(defMap, defs)

		if desc, _ := defMap["description"].(string); desc != "" {
			writeDocComment(&buf, goName, desc)
		}

		if len(props) == 0 {
			aliasType := resolveGoType(defMap, defs, name)
			if aliasType == goName {
				aliasType = "any"
			}
			fmt.Fprintf(&buf, "type %s = %s\n\n", goName, aliasType)
			continue
		}

		fmt.Fprintf(&buf, "type %s struct {\n", goName)
		propNames := make([]string, 0, len(props))
		for pName := range props {
			propNames = append(propNames, pName)
		}
		sort.Strings(propNames)

		usedFields := make(map[string]int)
		for _, pName := range propNames {
			propSchema, _ := props[pName].(map[string]any)
			fieldName := uniqueFieldName(pName, usedFields)
			goType := resolveFieldType(propSchema, defs, name)
			tag := pName
			if !reqSet[pName] {
				tag += ",omitempty"
				if shouldPointerize(goType) {
					goType = "*" + goType
				}
			}
			fmt.Fprintf(&buf, "\t%s %s `json:%q`\n", fieldName, goType, tag)
		}
		fmt.Fprintf(&buf, "}\n\n")
	}

	formatted, err := format.Source(buf.Bytes())
	if err != nil {
		return nil, fmt.Errorf("gofmt %s: %w\n%s", pkgName, err, buf.String())
	}
	return formatted, nil
}

func writeStringSliceVar(buf *bytes.Buffer, name string, vals []string) {
	fmt.Fprintf(buf, "var %s = []string{\n", name)
	for _, v := range vals {
		fmt.Fprintf(buf, "\t%q,\n", v)
	}
	fmt.Fprintf(buf, "}\n\n")
}

func writeDocComment(buf *bytes.Buffer, symbol, raw string) {
	lines := strings.Split(strings.TrimSpace(raw), "\n")
	if len(lines) > 2 {
		lines = lines[:2]
	}
	fmt.Fprintf(buf, "// %s %s\n", symbol, strings.TrimSpace(lines[0]))
	for _, ln := range lines[1:] {
		trimmed := strings.TrimSpace(ln)
		if trimmed != "" {
			fmt.Fprintf(buf, "// %s\n", trimmed)
		}
	}
}

func mergedProperties(defMap, defs map[string]any) map[string]any {
	out := make(map[string]any)
	if allOf, ok := defMap["allOf"].([]any); ok {
		for _, part := range allOf {
			partMap, ok := part.(map[string]any)
			if !ok {
				continue
			}
			if ref, ok := partMap["$ref"].(string); ok {
				if target, exists := defs[refBaseName(ref)].(map[string]any); exists {
					for k, v := range mergedProperties(target, defs) {
						out[k] = v
					}
				}
			}
			for k, v := range mergedProperties(partMap, defs) {
				out[k] = v
			}
		}
	}
	if props, ok := defMap["properties"].(map[string]any); ok {
		for k, v := range props {
			out[k] = v
		}
	}
	return out
}

func mergedRequired(defMap, defs map[string]any) map[string]bool {
	out := make(map[string]bool)
	if allOf, ok := defMap["allOf"].([]any); ok {
		for _, part := range allOf {
			partMap, ok := part.(map[string]any)
			if !ok {
				continue
			}
			if ref, ok := partMap["$ref"].(string); ok {
				if target, exists := defs[refBaseName(ref)].(map[string]any); exists {
					for k := range mergedRequired(target, defs) {
						out[k] = true
					}
				}
			}
			for k := range mergedRequired(partMap, defs) {
				out[k] = true
			}
		}
	}
	if reqs, ok := defMap["required"].([]any); ok {
		for _, r := range reqs {
			if rs, ok := r.(string); ok {
				out[rs] = true
			}
		}
	}
	return out
}

func resolveGoType(schema, defs map[string]any, selfName string) string {
	if schema == nil {
		return "any"
	}
	if ref, ok := schema["$ref"].(string); ok {
		base := refBaseName(ref)
		if base == selfName {
			return "any"
		}
		if _, exists := defs[base]; exists {
			return exportIdent(base)
		}
	}
	t, _ := schema["type"].(string)
	switch t {
	case "string":
		return "string"
	case "integer":
		return "int64"
	case "number":
		return "float64"
	case "boolean":
		return "bool"
	case "array":
		items, _ := schema["items"].(map[string]any)
		elem := resolveGoType(items, defs, selfName)
		if elem == selfName {
			elem = "any"
		}
		return "[]" + elem
	case "object":
		return "map[string]any"
	default:
		return "any"
	}
}

func resolveFieldType(schema, defs map[string]any, parentDef string) string {
	if schema == nil {
		return "any"
	}
	if ref, ok := schema["$ref"].(string); ok {
		base := refBaseName(ref)
		if target, exists := defs[base].(map[string]any); exists {
			// Avoid direct value recursion inside Go structs.
			if base == parentDef || hasCyclesTo(base, parentDef, defs, map[string]bool{}) {
				return "any"
			}
			if len(mergedProperties(target, defs)) > 0 {
				return exportIdent(base)
			}
			return resolveGoType(target, defs, parentDef)
		}
	}
	t, _ := schema["type"].(string)
	if t == "object" {
		if addl, ok := schema["additionalProperties"].(map[string]any); ok {
			valType := resolveFieldType(addl, defs, parentDef)
			return "map[string]" + valType
		}
		return "map[string]any"
	}
	if t == "array" {
		items, _ := schema["items"].(map[string]any)
		return "[]" + resolveFieldType(items, defs, parentDef)
	}
	return resolveGoType(schema, defs, parentDef)
}

func hasCyclesTo(cur, target string, defs map[string]any, seen map[string]bool) bool {
	if seen[cur] {
		return false
	}
	seen[cur] = true
	defMap, ok := defs[cur].(map[string]any)
	if !ok {
		return false
	}
	for _, prop := range mergedProperties(defMap, defs) {
		pm, ok := prop.(map[string]any)
		if !ok {
			continue
		}
		if ref, ok := pm["$ref"].(string); ok {
			next := refBaseName(ref)
			if next == target || hasCyclesTo(next, target, defs, seen) {
				return true
			}
		}
	}
	return false
}

func shouldPointerize(goType string) bool {
	switch goType {
	case "string", "int64", "float64", "bool", "any":
		return false
	}
	if strings.HasPrefix(goType, "[]") || strings.HasPrefix(goType, "map[") {
		return false
	}
	return true
}

func uniqueFieldName(raw string, used map[string]int) string {
	cleaned := strings.TrimPrefix(raw, "$")
	cleaned = strings.TrimPrefix(cleaned, "_")
	if strings.HasPrefix(raw, "_meta") {
		cleaned = "Meta"
	}
	candidate := exportIdent(cleaned)
	if candidate == "" {
		candidate = "Field"
	}
	if cnt := used[candidate]; cnt > 0 {
		used[candidate] = cnt + 1
		return fmt.Sprintf("%s%d", candidate, cnt+1)
	}
	used[candidate] = 1
	return candidate
}

func exportIdent(raw string) string {
	var b strings.Builder
	upperNext := true
	for _, r := range raw {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) {
			upperNext = true
			continue
		}
		if upperNext {
			b.WriteRune(unicode.ToUpper(r))
			upperNext = false
		} else {
			b.WriteRune(r)
		}
	}
	res := b.String()
	if res == "" {
		return ""
	}
	if unicode.IsDigit(rune(res[0])) {
		res = "X" + res
	}
	return res
}

func writeRegistry(outBase string, releases []releaseCapabilities) error {
	var buf bytes.Buffer
	buf.WriteString("// Code generated by cmd/mcpgen from docs/specs/mcp/*/schema.yaml. DO NOT EDIT.\n\n")
	buf.WriteString("package spec\n\n")

	latest := releases[len(releases)-1].Version
	fmt.Fprintf(&buf, "// DefaultVersion is the latest official MCP specification release.\n")
	fmt.Fprintf(&buf, "const DefaultVersion = %q\n\n", latest)

	buf.WriteString(`// SpecInfo describes an official MCP release compiled from docs/specs/mcp/<version>/schema.yaml.
type SpecInfo struct {
	Version                       string   ` + "`json:\"version\"`" + `
	Label                         string   ` + "`json:\"label\"`" + `
	Summary                       string   ` + "`json:\"summary\"`" + `
	SchemaDialect                 string   ` + "`json:\"schema_dialect\"`" + `
	SchemaDefCount                int      ` + "`json:\"schema_def_count\"`" + `
	TransportMode                 string   ` + "`json:\"transport_mode\"`" + `
	DefaultTransport              string   ` + "`json:\"default_transport\"`" + `
	AllowedTransports             []string ` + "`json:\"allowed_transports\"`" + `
	SupportsSessions              bool     ` + "`json:\"supports_sessions\"`" + `
	RequiresInitialize            bool     ` + "`json:\"requires_initialize\"`" + `
	SupportsBatching              bool     ` + "`json:\"supports_batching\"`" + `
	RequiresProtocolVersionHeader bool     ` + "`json:\"requires_protocol_version_header\"`" + `
	RequiresMirroredHeaders       bool     ` + "`json:\"requires_mirrored_headers\"`" + `
	SupportsServerDiscover        bool     ` + "`json:\"supports_server_discover\"`" + `
	SupportsSubscriptionsPost     bool     ` + "`json:\"supports_subscriptions_post\"`" + `
	SupportsTasks                 bool     ` + "`json:\"supports_tasks\"`" + `
	SupportsStructuredContent     bool     ` + "`json:\"supports_structured_content\"`" + `
	SupportsElicitation           bool     ` + "`json:\"supports_elicitation\"`" + `
	SupportsResultType            bool     ` + "`json:\"supports_result_type\"`" + `
	ClientRequestMethods          []string ` + "`json:\"client_request_methods\"`" + `
	ClientNotificationMethods     []string ` + "`json:\"client_notification_methods\"`" + `
	ServerNotificationMethods     []string ` + "`json:\"server_notification_methods\"`" + `
	defsKey                       string
}

var generatedSpecs = []SpecInfo{
`)
	for _, r := range releases {
		fmt.Fprintf(&buf, "\t{\n")
		fmt.Fprintf(&buf, "\t\tVersion: %q,\n", r.Version)
		fmt.Fprintf(&buf, "\t\tLabel: %q,\n", r.Label)
		fmt.Fprintf(&buf, "\t\tSummary: %q,\n", r.Summary)
		fmt.Fprintf(&buf, "\t\tSchemaDialect: %q,\n", r.SchemaDialect)
		fmt.Fprintf(&buf, "\t\tSchemaDefCount: %d,\n", r.DefCount)
		fmt.Fprintf(&buf, "\t\tTransportMode: %q,\n", r.TransportMode)
		fmt.Fprintf(&buf, "\t\tDefaultTransport: %q,\n", r.DefaultTransport)
		fmt.Fprintf(&buf, "\t\tAllowedTransports: %#v,\n", r.AllowedTransports)
		fmt.Fprintf(&buf, "\t\tSupportsSessions: %v,\n", r.SupportsSessions)
		fmt.Fprintf(&buf, "\t\tRequiresInitialize: %v,\n", r.RequiresInitialize)
		fmt.Fprintf(&buf, "\t\tSupportsBatching: %v,\n", r.SupportsBatching)
		fmt.Fprintf(&buf, "\t\tRequiresProtocolVersionHeader: %v,\n", r.RequiresProtocolVersionHdr)
		fmt.Fprintf(&buf, "\t\tRequiresMirroredHeaders: %v,\n", r.RequiresMirroredHeaders)
		fmt.Fprintf(&buf, "\t\tSupportsServerDiscover: %v,\n", r.SupportsServerDiscover)
		fmt.Fprintf(&buf, "\t\tSupportsSubscriptionsPost: %v,\n", r.SupportsSubscriptionsPost)
		fmt.Fprintf(&buf, "\t\tSupportsTasks: %v,\n", r.SupportsTasks)
		fmt.Fprintf(&buf, "\t\tSupportsStructuredContent: %v,\n", r.SupportsStructuredContent)
		fmt.Fprintf(&buf, "\t\tSupportsElicitation: %v,\n", r.SupportsElicitation)
		fmt.Fprintf(&buf, "\t\tSupportsResultType: %v,\n", r.SupportsResultType)
		fmt.Fprintf(&buf, "\t\tClientRequestMethods: %#v,\n", r.ClientRequestMethods)
		fmt.Fprintf(&buf, "\t\tClientNotificationMethods: %#v,\n", r.ClientNotificationMethods)
		fmt.Fprintf(&buf, "\t\tServerNotificationMethods: %#v,\n", r.ServerNotificationMethods)
		fmt.Fprintf(&buf, "\t\tdefsKey: %q,\n", r.DefsKey)
		fmt.Fprintf(&buf, "\t},\n")
	}
	buf.WriteString(`}

// SupportedSpecs returns a copy of all generated MCP specifications ordered chronologically.
func SupportedSpecs() []SpecInfo {
	out := make([]SpecInfo, len(generatedSpecs))
	copy(out, generatedSpecs)
	return out
}

// SupportedVersions returns the list of official MCP version strings supported.
func SupportedVersions() []string {
	out := make([]string, len(generatedSpecs))
	for i, s := range generatedSpecs {
		out[i] = s.Version
	}
	return out
}

// GetSpec looks up generated specification metadata by MCP version date.
func GetSpec(version string) (SpecInfo, bool) {
	for _, s := range generatedSpecs {
		if s.Version == version {
			return s, true
		}
	}
	return SpecInfo{}, false
}

// IsSupported reports whether version matches a generated official MCP specification.
func IsSupported(version string) bool {
	_, ok := GetSpec(version)
	return ok
}
`)

	formatted, err := format.Source(buf.Bytes())
	if err != nil {
		return fmt.Errorf("gofmt registry.gen.go: %w", err)
	}
	return os.WriteFile(filepath.Join(outBase, "registry.gen.go"), formatted, 0o644)
}
