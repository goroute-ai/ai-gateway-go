package gateway_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"

	"github.com/goroute-ai/ai-gateway-go/pkg/gateway"
)

func ExampleNew_remote() {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"chatcmpl-1","object":"chat.completion","model":"gpt-4o-mini","choices":[{"index":0,"message":{"role":"assistant","content":"pong"},"finish_reason":"stop"}]}`))
	}))
	defer srv.Close()

	client, err := gateway.New(
		gateway.WithRemote(srv.URL, "sk-gw-example"),
		gateway.WithHTTPClient(srv.Client()),
		gateway.WithSilentLogs(),
	)
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	defer client.Close()

	res, err := client.Chat(context.Background(), "gpt-4o-mini", "ping")
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	fmt.Println(res.Content)
	// Output: pong
}

func ExampleGuardrailScannerFunc() {
	scanner := gateway.GuardrailScannerFunc(func(ctx context.Context, req gateway.GuardrailScanRequest) (gateway.GuardrailScanResult, error) {
		if len(req.Texts) > 0 && req.Texts[0] == "forbidden" {
			return gateway.GuardrailScanResult{
				Decision:   gateway.GuardrailDecisionBlock,
				Violations: []string{"blocked_keyword"},
			}, nil
		}
		return gateway.GuardrailScanResult{Decision: gateway.GuardrailDecisionAllow}, nil
	})

	res, err := scanner.Scan(context.Background(), gateway.GuardrailScanRequest{
		OrgID:     "org-1",
		Direction: "input",
		Texts:     []string{"forbidden"},
	})
	fmt.Println(err == nil, res.Decision, res.Violations[0])
	// Output: true block blocked_keyword
}
