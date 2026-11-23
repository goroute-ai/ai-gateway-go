package a2a

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"syscall"
	"time"

	pb "github.com/goroute-ai/ai-gateway-go/internal/a2a/pb"
	a2aspec "github.com/goroute-ai/ai-gateway-go/internal/a2a/spec"
	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/observability"
	"github.com/goroute-ai/ai-gateway-go/internal/security/network"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

func (s *RouterService) dialUpstreamGRPC(ctx context.Context, agent *domain.A2AAgent) (*grpc.ClientConn, context.Context, error) {
	if agent == nil || strings.TrimSpace(agent.EndpointURL) == "" {
		return nil, ctx, ErrInvalidParams("upstream gRPC agent endpoint_url is empty")
	}

	rawURL := strings.TrimSpace(agent.EndpointURL)
	var parsed *url.URL
	var err error
	if strings.Contains(rawURL, "://") {
		parsed, err = url.Parse(rawURL)
		if err != nil {
			return nil, ctx, ErrInvalidParams(fmt.Sprintf("invalid upstream gRPC endpoint_url %q: %v", rawURL, err))
		}
	} else {
		parsed = &url.URL{
			Scheme: "http",
			Host:   rawURL,
		}
	}

	scheme := strings.ToLower(parsed.Scheme)
	var validateScheme string
	useTLS := false
	switch scheme {
	case "grpcs", "https":
		validateScheme = "https"
		useTLS = true
	case "grpc", "http", "":
		validateScheme = "http"
		useTLS = false
	default:
		return nil, ctx, ErrInvalidParams(fmt.Sprintf("unsupported upstream gRPC scheme %q", parsed.Scheme))
	}

	hostPort := parsed.Host
	if hostPort == "" {
		return nil, ctx, ErrInvalidParams(fmt.Sprintf("missing host in upstream gRPC endpoint_url %q", rawURL))
	}
	if _, _, splitErr := net.SplitHostPort(hostPort); splitErr != nil {
		if useTLS {
			hostPort = net.JoinHostPort(hostPort, "443")
		} else {
			hostPort = net.JoinHostPort(hostPort, "80")
		}
	}

	policy := s.netPolicy
	if policy == nil {
		policy, _ = network.NewPolicy(config.OutboundSSRFConfig{})
	}
	valURL := &url.URL{
		Scheme: validateScheme,
		Host:   hostPort,
	}
	if err := policy.ValidateURL(valURL); err != nil {
		return nil, ctx, ErrInvalidAgentResponse(fmt.Sprintf("upstream gRPC target blocked by SSRF policy: %v", err))
	}

	resolver := network.NewSafeResolver(policy)
	dialTimeout := policy.DialTimeout
	if dialTimeout <= 0 {
		dialTimeout = 10 * time.Second
	}
	dialer := &net.Dialer{
		Timeout:   dialTimeout,
		KeepAlive: 30 * time.Second,
		Control: func(netProto, address string, c syscall.RawConn) error {
			h, _, sErr := net.SplitHostPort(address)
			if sErr != nil {
				h = address
			}
			if ip := net.ParseIP(h); ip != nil {
				return policy.ValidateIP(ip)
			}
			return nil
		},
	}

	var creds credentials.TransportCredentials
	if useTLS {
		serverName, _, sErr := net.SplitHostPort(hostPort)
		if sErr != nil {
			serverName = hostPort
		}
		creds = credentials.NewTLS(&tls.Config{
			MinVersion: tls.VersionTLS12,
			ServerName: serverName,
		})
	} else {
		creds = insecure.NewCredentials()
	}

	conn, err := grpc.NewClient(
		"passthrough:///"+hostPort,
		grpc.WithTransportCredentials(creds),
		grpc.WithContextDialer(func(dCtx context.Context, addr string) (net.Conn, error) {
			h, p, sErr := net.SplitHostPort(addr)
			if sErr != nil {
				return nil, fmt.Errorf("split gRPC addr %q: %w", addr, sErr)
			}
			validIPs, lErr := resolver.LookupAndValidate(dCtx, h)
			if lErr != nil {
				return nil, lErr
			}
			var lastErr error
			for _, ip := range validIPs {
				target := net.JoinHostPort(ip.String(), p)
				c, dErr := dialer.DialContext(dCtx, "tcp", target)
				if dErr == nil {
					return c, nil
				}
				lastErr = dErr
			}
			return nil, fmt.Errorf("gRPC dial failed: %w", lastErr)
		}),
	)
	if err != nil {
		return nil, ctx, ErrInvalidAgentResponse(fmt.Sprintf("create gRPC client: %v", err))
	}

	headerCarrier, err := http.NewRequestWithContext(ctx, http.MethodPost, valURL.String(), nil)
	if err != nil {
		_ = conn.Close()
		return nil, ctx, ErrInternal(fmt.Sprintf("build gRPC header carrier: %v", err))
	}
	if err := s.applyUpstreamAuth(agent, headerCarrier); err != nil {
		_ = conn.Close()
		return nil, ctx, err
	}
	observability.InjectTraceHeaders(ctx, headerCarrier)

	mdPairs := []string{
		strings.ToLower(HeaderA2AVersion), a2aspec.SupportedA2AVersion,
		"x-a2a-agent-slug", agent.Slug,
	}
	if opts := CallOptionsFromContext(ctx); len(opts.Extensions) > 0 {
		mdPairs = append(mdPairs, strings.ToLower(HeaderA2AExtensions), strings.Join(opts.Extensions, ", "))
	}
	for k, vals := range headerCarrier.Header {
		lk := strings.ToLower(strings.TrimSpace(k))
		if lk == "" {
			continue
		}
		for _, v := range vals {
			if strings.TrimSpace(v) != "" {
				mdPairs = append(mdPairs, lk, v)
			}
		}
	}

	outCtx := metadata.AppendToOutgoingContext(ctx, mdPairs...)
	return conn, outCtx, nil
}

func (s *RouterService) invokeUpstreamGRPCSync(
	ctx context.Context,
	agent *domain.A2AAgent,
	req *a2aspec.SendMessageRequest,
) (*a2aspec.SendMessageResponse, error) {
	conn, rpcCtx, err := s.dialUpstreamGRPC(ctx, agent)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()

	pbReq, err := specToPB[pb.SendMessageRequest](req)
	if err != nil {
		return nil, ErrInvalidParams(fmt.Sprintf("encode gRPC SendMessageRequest: %v", err))
	}

	callCtx, cancel := context.WithTimeout(rpcCtx, 60*time.Second)
	defer cancel()

	client := pb.NewA2AServiceClient(conn)
	pbResp, err := client.SendMessage(callCtx, pbReq)
	if err != nil {
		return nil, ErrInvalidAgentResponse(fmt.Sprintf("upstream gRPC SendMessage failed: %v", err))
	}

	out, err := pbToSpec[a2aspec.SendMessageResponse](pbResp)
	if err != nil {
		return nil, ErrInvalidAgentResponse(fmt.Sprintf("decode upstream gRPC SendMessageResponse: %v", err))
	}
	if out.Task == nil && out.Message == nil {
		return nil, ErrInvalidAgentResponse("invalid upstream gRPC SendMessageResponse: neither task nor message set")
	}
	return out, nil
}

func (s *RouterService) invokeUpstreamGRPCStream(
	ctx context.Context,
	agent *domain.A2AAgent,
	req *a2aspec.SendMessageRequest,
	onFrame func(*a2aspec.StreamResponse) error,
) (bool, error) {
	conn, rpcCtx, err := s.dialUpstreamGRPC(ctx, agent)
	if err != nil {
		return false, err
	}
	defer func() { _ = conn.Close() }()

	pbReq, err := specToPB[pb.SendMessageRequest](req)
	if err != nil {
		return false, ErrInvalidParams(fmt.Sprintf("encode gRPC SendStreamingMessageRequest: %v", err))
	}

	client := pb.NewA2AServiceClient(conn)
	stream, err := client.SendStreamingMessage(rpcCtx, pbReq)
	if err != nil {
		return false, ErrInvalidAgentResponse(fmt.Sprintf("upstream gRPC SendStreamingMessage failed: %v", err))
	}

	for {
		pbFrame, recvErr := stream.Recv()
		if errors.Is(recvErr, io.EOF) {
			break
		}
		if recvErr != nil {
			return true, ErrInvalidAgentResponse(fmt.Sprintf("read upstream gRPC stream: %v", recvErr))
		}
		frame, convErr := pbToSpec[a2aspec.StreamResponse](pbFrame)
		if convErr != nil {
			return true, ErrInvalidAgentResponse(fmt.Sprintf("decode upstream gRPC StreamResponse: %v", convErr))
		}
		if frame.Task == nil && frame.Message == nil && frame.StatusUpdate == nil && frame.ArtifactUpdate == nil {
			return true, ErrInvalidAgentResponse("invalid upstream gRPC StreamResponse: empty frame")
		}
		if onFrame != nil {
			if cbErr := onFrame(frame); cbErr != nil {
				return true, cbErr
			}
		}
	}
	return true, nil
}

func (s *RouterService) cancelUpstreamGRPCTask(ctx context.Context, agent *domain.A2AAgent, upstreamTaskID string) {
	cCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	conn, rpcCtx, err := s.dialUpstreamGRPC(cCtx, agent)
	if err != nil {
		return
	}
	defer func() { _ = conn.Close() }()

	client := pb.NewA2AServiceClient(conn)
	_, _ = client.CancelTask(rpcCtx, &pb.CancelTaskRequest{Id: upstreamTaskID})
}
