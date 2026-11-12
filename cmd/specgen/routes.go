package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"path"
	"strconv"
)

var supportedHTTPMethods = map[string]bool{
	"get": true, "post": true, "put": true, "patch": true, "delete": true,
	"options": true, "head": true, "trace": true,
}

// checkDataPlaneRouteCoverage keeps the primary /v1 chi route group aligned
// with the gateway OpenAPI contract. Alias, protocol, and control-plane route
// groups are tracked separately and are not covered by this initial gate.
func checkDataPlaneRouteCoverage(serverFile string, specPaths map[string]any) error {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, serverFile, nil, 0)
	if err != nil {
		return fmt.Errorf("parse gateway routes: %w", err)
	}

	registered := make(map[string]bool)
	ast.Inspect(file, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok || len(call.Args) < 2 {
			return true
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || selector.Sel.Name != "Route" {
			return true
		}
		receiver, ok := selector.X.(*ast.Ident)
		if !ok || receiver.Name != "r" {
			return true
		}
		prefix, ok := stringLiteral(call.Args[0])
		if !ok || prefix != "/v1" {
			return true
		}
		callback, ok := call.Args[1].(*ast.FuncLit)
		if !ok || len(callback.Type.Params.List) == 0 || len(callback.Type.Params.List[0].Names) == 0 {
			return true
		}
		routerName := callback.Type.Params.List[0].Names[0].Name
		for _, statement := range callback.Body.List {
			ast.Inspect(statement, func(child ast.Node) bool {
				routeCall, ok := child.(*ast.CallExpr)
				if !ok || len(routeCall.Args) == 0 {
					return true
				}
				routeSelector, ok := routeCall.Fun.(*ast.SelectorExpr)
				if !ok || routeSelector.Sel == nil {
					return true
				}
				routeReceiver, ok := routeSelector.X.(*ast.Ident)
				if !ok || routeReceiver.Name != routerName {
					return true
				}
				method := routeSelector.Sel.Name
				if !supportedHTTPMethods[lower(method)] {
					return true
				}
				suffix, ok := stringLiteral(routeCall.Args[0])
				if !ok {
					return true
				}
				registered[lower(method)+" "+path.Join(prefix, suffix)] = true
				return true
			})
		}
		return false
	})

	var missing, stale []string
	for operation := range registered {
		method, route, _ := splitOperation(operation)
		pathItem, exists := specPaths[route]
		if !exists || !hasMethod(pathItem, method) {
			missing = append(missing, operation)
		}
	}
	for route, rawItem := range specPaths {
		if route != "/v1" && !hasPrefix(route, "/v1/") {
			continue
		}
		item, ok := rawItem.(map[string]any)
		if !ok {
			continue
		}
		for method := range supportedHTTPMethods {
			if _, declared := item[method]; !declared {
				continue
			}
			operation := method + " " + route
			if !registered[operation] {
				stale = append(stale, operation)
			}
		}
	}
	if len(missing) != 0 || len(stale) != 0 {
		sortStrings(missing)
		sortStrings(stale)
		return fmt.Errorf("/v1 route/spec mismatch: undocumented registered operations=%v; documented operations without /v1 handlers=%v", missing, stale)
	}
	return nil
}

func stringLiteral(expr ast.Expr) (string, bool) {
	literal, ok := expr.(*ast.BasicLit)
	if !ok || literal.Kind != token.STRING {
		return "", false
	}
	value, err := strconv.Unquote(literal.Value)
	return value, err == nil
}

func splitOperation(operation string) (method, route string, ok bool) {
	for i, r := range operation {
		if r == ' ' {
			return operation[:i], operation[i+1:], true
		}
	}
	return "", "", false
}

func hasMethod(rawItem any, method string) bool {
	item, ok := rawItem.(map[string]any)
	if !ok {
		return false
	}
	_, ok = item[method]
	return ok
}

func lower(value string) string {
	for i := range value {
		if value[i] >= 'A' && value[i] <= 'Z' {
			value = value[:i] + string(value[i]+('a'-'A')) + value[i+1:]
		}
	}
	return value
}

func hasPrefix(value, prefix string) bool {
	return len(value) >= len(prefix) && value[:len(prefix)] == prefix
}

func sortStrings(values []string) {
	// Avoid another helper dependency in this small build-time tool.
	for i := 0; i < len(values); i++ {
		for j := i + 1; j < len(values); j++ {
			if values[j] < values[i] {
				values[i], values[j] = values[j], values[i]
			}
		}
	}
}
