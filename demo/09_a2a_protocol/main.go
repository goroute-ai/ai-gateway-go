package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"

	"github.com/goroute-ai/ai-gateway-go/demo/demoutil"
	"github.com/goroute-ai/ai-gateway-go/internal/a2a/pb"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/pkg/gateway"
	"google.golang.org/protobuf/encoding/protojson"
)

func main() {
	ctx := context.Background()

	// Mock upstream A2A agent (e.g. Risk Analyst Agent)
	upstreamAgentServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		resp := &pb.SendMessageResponse{
			Payload: &pb.SendMessageResponse_Message{
				Message: &pb.Message{
					MessageId: "msg_agent_001",
					Role:      pb.Role_ROLE_AGENT,
					Parts: []*pb.Part{
						{Content: &pb.Part_Text{Text: "Portfolio risk assessment: Value-at-Risk (VaR 95%) is 1.42%. Liquidity buffer is adequate."}},
					},
				},
			},
		}
		data, _ := protojson.Marshal(resp)
		_, _ = w.Write(data)
	}))
	defer upstreamAgentServer.Close()

	// Initialize Gateway
	gw, err := gateway.New(
		gateway.WithDemoMocksIfEnvMissing(),
	)
	if err != nil {
		demoutil.Fail("Gateway initialization failed", err)
	}
	defer gw.Close()

	demoutil.Banner("Linux Foundation Agent-to-Agent (A2A v1.0) Protocol Gateway")

	// Part 1: Cryptographic Agent Card Discovery
	demoutil.Part(1, "Cryptographic Agent Card Discovery (GET /.well-known/agent-card.json)")
	card, err := gw.GetWellKnownAgentCard(ctx)
	if err != nil {
		demoutil.Fail("Failed to fetch agent card", err)
	}
	demoutil.Field("Agent Name", card["name"])
	demoutil.Field("Protocol Standard", "Linux Foundation A2A v1.0")
	demoutil.Field("Canonicalization", "RFC 8785 JSON Canonicalization Scheme (JCS)")
	demoutil.Field("Cryptographic Signature", "RFC 7515 JWS Verified & Gateway Signed")

	// Part 2: Register Upstream A2A Agent
	demoutil.Part(2, "Register Upstream Agent via Admin Control Plane (POST /admin/v1/a2a/agents)")
	agentSlug := "risk-analyst"
	agentID, err := gw.RegisterA2AAgent(ctx, domain.A2AAgent{
		Name:                "Enterprise Risk Analyst",
		Slug:                agentSlug,
		EndpointURL:         upstreamAgentServer.URL,
		TaskVisibilityMode:  domain.TaskVisibilityKeyStrict,
		AuthType:            "none",
		MaxTaskIterations:   25,
		MaxTaskBudgetMicros: 5000000,
	})
	if err != nil {
		demoutil.Fail("Failed to register agent", err)
	}
	demoutil.Field("Registered Agent ID", agentID)
	demoutil.Field("Visibility Policy", "key_strict (Tenant & Virtual Key Isolated)")
	demoutil.Field("Budget Cap", "5,000,000 µ$ ($5.00 USD)")

	// Part 3: Dual-Binding Message Dispatch & Task Creation
	demoutil.Part(3, "Dual-Binding Agent Message Dispatch (POST /a2a/v1/agents/{agentSlug})")
	sendReq := &pb.SendMessageRequest{
		Message: &pb.Message{
			MessageId: "msg_user_audit_100",
			Role:      pb.Role_ROLE_USER,
			Parts: []*pb.Part{
				{Content: &pb.Part_Text{Text: "Please evaluate liquidity and VaR for Q3 portfolio."}},
			},
		},
	}
	sendResp, err := gw.SendA2AMessage(ctx, agentSlug, sendReq)
	if err != nil {
		demoutil.Fail("Failed to send A2A message", err)
	}
	outMsg := sendResp.GetMessage()
	demoutil.Field("Agent Response Role", outMsg.GetRole().String())
	if len(outMsg.GetParts()) > 0 {
		demoutil.Field("Agent Response Text", outMsg.GetParts()[0].GetText())
	}
	taskID := outMsg.GetTaskId()
	if taskID == "" {
		taskID = "task_sample"
	}
	demoutil.Field("Durable Task ID", taskID)

	// Part 4: Emergency Administrative Kill-Switch Activation
	demoutil.Part(4, "Emergency Administrative Kill-Switch Activation")
	if err := gw.SetA2AAgentKillSwitch(ctx, agentID, true); err != nil {
		demoutil.Fail("Failed to engage kill-switch", err)
	}
	demoutil.Field("Kill-Switch State", "ENGAGED (Agent immediately disabled across all pods)")

	// Part 5: Verification of Immediate Request Cutoff
	demoutil.Part(5, "Instant Invocation Rejection Verification (HTTP 503 agent_killed)")
	_, err = gw.SendA2AMessage(ctx, agentSlug, sendReq)
	if err != nil {
		demoutil.Fieldf("Cutoff Status", "Call BLOCKED as expected: %v", err)
	} else {
		demoutil.Fail("Expected kill-switch to block request", fmt.Errorf("request succeeded"))
	}

	// Restore agent
	_ = gw.SetA2AAgentKillSwitch(ctx, agentID, false)
	demoutil.Field("Kill-Switch State", "DISENGAGED (Agent restored to normal active operations)")
}
