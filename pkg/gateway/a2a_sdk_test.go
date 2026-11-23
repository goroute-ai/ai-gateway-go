package gateway_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/goroute-ai/ai-gateway-go/pkg/gateway"
)

func TestSDKA2AOpenAPILifecycle(t *testing.T) {
	ctx := context.Background()

	var upstreamURL string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/agent-card.json":
			w.Header().Set("Content-Type", "application/a2a+json")
			_, _ = fmt.Fprintf(w, `{
				"name": "SDK Agent",
				"description": "SDK test upstream",
				"version": "1.0.0",
				"capabilities": {"streaming": true, "pushNotifications": true, "extendedAgentCard": true},
				"defaultInputModes": ["text/plain"],
				"defaultOutputModes": ["text/plain"],
				"skills": [],
				"supportedInterfaces": [{"protocolBinding": "HTTP+JSON", "protocolVersion": "1.0", "url": %q}]
			}`, upstreamURL)
		case "/message:stream":
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = w.Write([]byte(`data: {"message":{"messageId":"m_stream","role":"ROLE_AGENT","parts":[{"text":"hello stream"}]}}` + "\n\n"))
		default:
			w.Header().Set("Content-Type", "application/a2a+json")
			_, _ = w.Write([]byte(`{"task":{"id":"up_task_1","contextId":"ctx_sdk_1","status":{"state":"TASK_STATE_WORKING","message":{"messageId":"m1","role":"ROLE_AGENT","parts":[{"text":"working"}]}}}}`))
		}
	}))
	defer upstream.Close()
	upstreamURL = upstream.URL

	gw, err := gateway.New(
		gateway.WithAllowPrivateNetworks(),
		gateway.WithDemoMocksIfEnvMissing(),
		gateway.WithSilentLogs(),
	)
	if err != nil {
		t.Fatalf("gateway.New: %v", err)
	}
	defer gw.Close()

	vk, err := gw.CreateVirtualKey(ctx, gateway.VirtualKeyRequest{
		Name:             "sdk-a2a-key",
		Role:             "developer",
		AllowedEndpoints: []string{"*"},
		AllowedA2AAgents: []string{"sdk-agent"},
	})
	if err != nil {
		t.Fatalf("CreateVirtualKey: %v", err)
	}
	client := gw.WithKey(vk.Key)

	// 1. Register A2A agent via SDK
	agentID, err := gw.AddA2AAgent(ctx, gateway.A2AAgentConfig{
		Name:                  "SDK Agent",
		Slug:                  "sdk-agent",
		EndpointURL:           upstream.URL,
		AgentCardURL:          upstream.URL + "/.well-known/agent-card.json",
		ExtendedAgentCardJSON: fmt.Sprintf(`{"name":"SDK Agent Extended","description":"Extended","version":"1.0.0","capabilities":{"extendedAgentCard":true},"defaultInputModes":["text/plain"],"defaultOutputModes":["text/plain"],"skills":[],"supportedInterfaces":[{"protocolBinding":"HTTP+JSON","protocolVersion":"1.0","url":%q}]}`, upstream.URL),
		IsPublicCard:          true,
		ProtocolBinding:       "HTTP+JSON",
	})
	if err != nil {
		t.Fatalf("AddA2AAgent: %v", err)
	}

	// 2. Sync upstream AgentCard & fetch well-known + extended cards
	if _, err := gw.SyncA2AAgentCard(ctx, agentID, "", ""); err != nil {
		t.Fatalf("SyncA2AAgentCard: %v", err)
	}
	wellKnown, err := client.GetWellKnownAgentCard(ctx, "sdk-agent")
	if err != nil || wellKnown["name"] != "SDK Agent" {
		t.Fatalf("GetWellKnownAgentCard unexpected: err=%v card=%v", err, wellKnown)
	}
	extCard, err := client.GetA2AExtendedAgentCard(ctx, "sdk-agent")
	if err != nil || extCard["name"] != "SDK Agent Extended" {
		t.Fatalf("GetA2AExtendedAgentCard unexpected: err=%v card=%v", err, extCard)
	}

	// 3. SendA2AMessage
	sendResp, err := client.SendA2AMessage(ctx, "sdk-agent", &gateway.A2ASendMessageRequest{
		Message: gateway.NewA2ATextMessage("msg_sdk_1", gateway.A2ARoleUser, "start task"),
	})
	if err != nil || sendResp.Task == nil {
		t.Fatalf("SendA2AMessage failed: err=%v resp=%+v", err, sendResp)
	}
	taskID := sendResp.Task.Id

	// 4. List & Get Task
	listResp, err := client.ListA2ATasks(ctx, "sdk-agent", &gateway.A2AListTasksRequest{PageSize: 10})
	if err != nil || len(listResp.Tasks) == 0 {
		t.Fatalf("ListA2ATasks failed: err=%v resp=%+v", err, listResp)
	}
	fetched, err := client.GetA2ATask(ctx, "sdk-agent", taskID)
	if err != nil || fetched.Id != taskID {
		t.Fatalf("GetA2ATask failed: err=%v task=%+v", err, fetched)
	}

	// 5. Push config CRUD
	createdPush, err := client.CreateA2APushConfig(ctx, "sdk-agent", taskID, &gateway.A2ATaskPushNotificationConfig{
		Url:   "https://webhook.example.com/a2a",
		Token: "tok_sdk_1",
	})
	if err != nil || createdPush.Id == "" {
		t.Fatalf("CreateA2APushConfig failed: err=%v cfg=%+v", err, createdPush)
	}
	pushList, err := client.ListA2APushConfigs(ctx, "sdk-agent", taskID, 10, "")
	if err != nil || len(pushList.Configs) != 1 {
		t.Fatalf("ListA2APushConfigs failed: err=%v list=%+v", err, pushList)
	}
	gotPush, err := client.GetA2APushConfig(ctx, "sdk-agent", taskID, createdPush.Id)
	if err != nil || gotPush.Id != createdPush.Id {
		t.Fatalf("GetA2APushConfig failed: err=%v cfg=%+v", err, gotPush)
	}
	if err := client.DeleteA2APushConfig(ctx, "sdk-agent", taskID, createdPush.Id); err != nil {
		t.Fatalf("DeleteA2APushConfig failed: %v", err)
	}

	// 6. Cancel task & stream message
	canceled, err := client.CancelA2ATask(ctx, "sdk-agent", taskID)
	if err != nil || canceled.Status.State != gateway.A2ATaskStateCanceled {
		t.Fatalf("CancelA2ATask failed: err=%v task=%+v", err, canceled)
	}

	var frames []gateway.A2AStreamResponse
	err = client.SendA2AStreamingMessage(ctx, "sdk-agent", &gateway.A2ASendMessageRequest{
		Message: gateway.NewA2ATextMessage("msg_sdk_2", gateway.A2ARoleUser, "stream please"),
	}, func(f gateway.A2AStreamResponse) error {
		frames = append(frames, f)
		return nil
	})
	if err != nil || len(frames) == 0 || frames[0].Message == nil {
		t.Fatalf("SendA2AStreamingMessage failed: err=%v frames=%+v", err, frames)
	}

	// 7. Admin update, outbox list, delete
	if _, err := gw.UpdateA2AAgent(ctx, agentID, map[string]any{"name": "SDK Agent v2"}); err != nil {
		t.Fatalf("UpdateA2AAgent: %v", err)
	}
	if _, err := gw.ListA2AOutboxEvents(ctx, "org_default", "", 10); err != nil {
		t.Fatalf("ListA2AOutboxEvents: %v", err)
	}
	if err := gw.DeleteA2AAgent(ctx, agentID); err != nil {
		t.Fatalf("DeleteA2AAgent: %v", err)
	}
	_ = json.Valid
}
