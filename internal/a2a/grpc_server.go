package a2a

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"

	"github.com/goroute-ai/ai-gateway-go/internal/a2a/pb"
	a2aspec "github.com/goroute-ai/ai-gateway-go/internal/a2a/spec"
	"github.com/goroute-ai/ai-gateway-go/internal/auth"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"
)

// GRPCServer implements all 11 lf.a2a.v1.A2AServiceServer RPCs as a thin protocol adapter
// over the OpenAPI-first RouterService and StreamSubscriber.
type GRPCServer struct {
	pb.UnimplementedA2AServiceServer
	router       *RouterService
	authSvc      *auth.Service
	authResolver *auth.AuthResolver
	rbac         *auth.RBACEngine
	streamSub    *StreamSubscriber
}

// NewGRPCServer constructs an A2A gRPC adapter backed by RouterService and auth services.
func NewGRPCServer(router *RouterService, authSvc *auth.Service, rbac *auth.RBACEngine) *GRPCServer {
	var streamSub *StreamSubscriber
	if router != nil && router.repo != nil {
		streamSub = NewStreamSubscriber(router.repo, rbac, router.redisFabric, router.cfg.StreamBufferCapacity)
	}
	return &GRPCServer{
		router:    router,
		authSvc:   authSvc,
		rbac:      rbac,
		streamSub: streamSub,
	}
}

// SetAuthResolver attaches the unified AuthResolver so gRPC inherits JWT/OIDC,
// OAuth introspection, access groups, and delegation narrowing.
func (s *GRPCServer) SetAuthResolver(resolver *auth.AuthResolver) {
	if s != nil {
		s.authResolver = resolver
	}
}

// SetStreamSubscriber attaches a custom StreamSubscriber instance.
func (s *GRPCServer) SetStreamSubscriber(sub *StreamSubscriber) {
	if s != nil {
		s.streamSub = sub
	}
}

// Register registers this gRPC service on the specified gRPC server.
func (s *GRPCServer) Register(srv grpc.ServiceRegistrar) {
	pb.RegisterA2AServiceServer(srv, s)
}

func (s *GRPCServer) authenticate(ctx context.Context) (*domain.IdentityContext, string, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, "", status.Error(codes.Unauthenticated, "missing grpc metadata")
	}

	var idCtx *domain.IdentityContext
	if s.authResolver != nil {
		synReq := &http.Request{
			Method: http.MethodPost,
			URL:    &url.URL{Path: "/a2a/v1"},
			Header: make(http.Header),
		}
		for k, vals := range md {
			for _, v := range vals {
				synReq.Header.Add(k, v)
			}
		}
		resolved, err := s.authResolver.ResolveRequest(ctx, synReq)
		if err != nil {
			return nil, "", status.Error(codes.Unauthenticated, "authentication failed: "+err.Error())
		}
		idCtx = resolved
	} else {
		authHeaders := md.Get("authorization")
		if len(authHeaders) == 0 {
			return nil, "", status.Error(codes.Unauthenticated, "missing authorization header in grpc metadata")
		}
		rawToken := strings.TrimSpace(authHeaders[0])
		rawToken = strings.TrimPrefix(rawToken, "Bearer ")
		rawToken = strings.TrimPrefix(rawToken, "bearer ")
		if s.authSvc == nil {
			return nil, "", status.Error(codes.Internal, "auth service not configured")
		}
		vkCtx, err := s.authSvc.AuthenticateVirtualKey(ctx, rawToken)
		if err != nil {
			return nil, "", status.Error(codes.Unauthenticated, "invalid virtual key: "+err.Error())
		}
		idCtx = vkCtx
	}

	if vals := md.Get("a2a-version"); len(vals) > 0 {
		ver := strings.TrimSpace(vals[0])
		if !a2aspec.IsSupportedA2AVersion(ver) {
			return nil, "", ErrVersionNotSupported("unsupported A2A-Version "+ver, ver).ToGRPCStatus()
		}
	}

	if s.rbac != nil {
		if err := s.rbac.AuthorizeEndpoint(idCtx, "/a2a/v1/agents"); err != nil {
			return nil, "", status.Error(codes.PermissionDenied, err.Error())
		}
	}

	agentSlug := ""
	if slugHeaders := md.Get("x-a2a-agent-slug"); len(slugHeaders) > 0 {
		agentSlug = strings.TrimSpace(slugHeaders[0])
	}

	if exts := md.Get("a2a-extensions"); len(exts) > 0 {
		ctx = ContextWithCallOptions(ctx, CallOptions{
			Version:    a2aspec.SupportedA2AVersion,
			Extensions: a2aspec.ParseExtensionsHeader(strings.Join(exts, ",")),
		})
	}
	_ = ctx
	return idCtx, agentSlug, nil
}

func authorizeGRPCMutation(idCtx *domain.IdentityContext) error {
	if idCtx != nil && (idCtx.KeyType == domain.KeyTypeReadOnly || idCtx.Role == domain.RoleViewer || idCtx.Role == domain.RoleOrgViewer) {
		return status.Error(codes.PermissionDenied, "read-only credentials cannot perform mutating A2A gRPC operations")
	}
	return nil
}

func (s *GRPCServer) enrichedContext(ctx context.Context) context.Context {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ctx
	}
	opts := CallOptions{Version: a2aspec.SupportedA2AVersion}
	if exts := md.Get("a2a-extensions"); len(exts) > 0 {
		opts.Extensions = a2aspec.ParseExtensionsHeader(strings.Join(exts, ","))
	}
	return ContextWithCallOptions(ctx, opts)
}

func (s *GRPCServer) resolveAgentSlug(ctx context.Context, idCtx *domain.IdentityContext, agentSlug, taskID string) (string, error) {
	if agentSlug != "" {
		return agentSlug, nil
	}
	if taskID != "" && s.router != nil && s.router.repo != nil && idCtx != nil {
		task, err := s.router.repo.GetA2ATask(ctx, taskID)
		if err == nil && task != nil && task.OrgID == idCtx.OrgID {
			agent, err := s.router.repo.GetA2AAgent(ctx, task.AgentID)
			if err == nil && agent != nil {
				return agent.Slug, nil
			}
		}
	}
	return "", status.Error(codes.InvalidArgument, "missing agent slug (specify via x-a2a-agent-slug metadata header or provide a valid task_id)")
}

// SendMessage implements lf.a2a.v1.A2AService.SendMessage.
func (s *GRPCServer) SendMessage(ctx context.Context, req *pb.SendMessageRequest) (*pb.SendMessageResponse, error) {
	idCtx, agentSlug, err := s.authenticate(ctx)
	if err != nil {
		return nil, err
	}
	if err := authorizeGRPCMutation(idCtx); err != nil {
		return nil, err
	}

	if agentSlug == "" && req.GetMessage() != nil {
		if req.GetMessage().GetMetadata() != nil {
			if val, ok := req.GetMessage().GetMetadata().Fields["agent_slug"]; ok {
				agentSlug = val.GetStringValue()
			}
		}
		if agentSlug == "" && req.GetMessage().GetTaskId() != "" {
			agentSlug, _ = s.resolveAgentSlug(ctx, idCtx, "", req.GetMessage().GetTaskId())
		}
	}
	if agentSlug == "" {
		return nil, status.Error(codes.InvalidArgument, "missing agent slug (specify via x-a2a-agent-slug metadata or message.metadata.agent_slug)")
	}

	specReq, convErr := pbToSpec[a2aspec.SendMessageRequest](req)
	if convErr != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid SendMessageRequest: "+convErr.Error())
	}

	specResp, svcErr := s.router.SendMessage(s.enrichedContext(ctx), idCtx, agentSlug, specReq)
	if svcErr != nil {
		return nil, NormalizeA2AError(svcErr).ToGRPCStatus()
	}

	pbResp, outErr := specToPB[pb.SendMessageResponse](specResp)
	if outErr != nil {
		return nil, status.Error(codes.Internal, "marshal SendMessageResponse: "+outErr.Error())
	}
	return pbResp, nil
}

// SendStreamingMessage implements lf.a2a.v1.A2AService.SendStreamingMessage.
func (s *GRPCServer) SendStreamingMessage(req *pb.SendMessageRequest, stream grpc.ServerStreamingServer[pb.StreamResponse]) error {
	ctx := stream.Context()
	idCtx, agentSlug, err := s.authenticate(ctx)
	if err != nil {
		return err
	}
	if err := authorizeGRPCMutation(idCtx); err != nil {
		return err
	}

	if agentSlug == "" && req.GetMessage() != nil {
		if req.GetMessage().GetMetadata() != nil {
			if val, ok := req.GetMessage().GetMetadata().Fields["agent_slug"]; ok {
				agentSlug = val.GetStringValue()
			}
		}
		if agentSlug == "" && req.GetMessage().GetTaskId() != "" {
			agentSlug, _ = s.resolveAgentSlug(ctx, idCtx, "", req.GetMessage().GetTaskId())
		}
	}
	if agentSlug == "" {
		return status.Error(codes.InvalidArgument, "missing agent slug")
	}

	specReq, convErr := pbToSpec[a2aspec.SendMessageRequest](req)
	if convErr != nil {
		return status.Error(codes.InvalidArgument, "invalid SendMessageRequest: "+convErr.Error())
	}

	svcErr := s.router.SendStreamingMessage(s.enrichedContext(ctx), idCtx, agentSlug, specReq, func(frame *a2aspec.StreamResponse, _ int64) error {
		pbFrame, mErr := specToPB[pb.StreamResponse](frame)
		if mErr != nil {
			return status.Error(codes.Internal, mErr.Error())
		}
		return stream.Send(pbFrame)
	})
	if svcErr != nil {
		return NormalizeA2AError(svcErr).ToGRPCStatus()
	}
	return nil
}

// GetTask implements lf.a2a.v1.A2AService.GetTask.
func (s *GRPCServer) GetTask(ctx context.Context, req *pb.GetTaskRequest) (*pb.Task, error) {
	idCtx, agentSlug, err := s.authenticate(ctx)
	if err != nil {
		return nil, err
	}
	if req.GetId() == "" {
		return nil, status.Error(codes.InvalidArgument, "task id is required")
	}
	agentSlug, err = s.resolveAgentSlug(ctx, idCtx, agentSlug, req.GetId())
	if err != nil {
		return nil, err
	}

	task, svcErr := s.router.GetTask(s.enrichedContext(ctx), idCtx, agentSlug, req.GetId(), req.HistoryLength)
	if svcErr != nil {
		return nil, NormalizeA2AError(svcErr).ToGRPCStatus()
	}
	pbTask, outErr := specToPB[pb.Task](task)
	if outErr != nil {
		return nil, status.Error(codes.Internal, outErr.Error())
	}
	return pbTask, nil
}

// ListTasks implements lf.a2a.v1.A2AService.ListTasks.
func (s *GRPCServer) ListTasks(ctx context.Context, req *pb.ListTasksRequest) (*pb.ListTasksResponse, error) {
	idCtx, agentSlug, err := s.authenticate(ctx)
	if err != nil {
		return nil, err
	}
	if agentSlug == "" {
		return nil, status.Error(codes.InvalidArgument, "missing agent slug (specify via x-a2a-agent-slug metadata header)")
	}
	specReq, convErr := pbToSpec[a2aspec.ListTasksRequest](req)
	if convErr != nil {
		return nil, status.Error(codes.InvalidArgument, convErr.Error())
	}

	resp, svcErr := s.router.ListTasks(s.enrichedContext(ctx), idCtx, agentSlug, specReq)
	if svcErr != nil {
		return nil, NormalizeA2AError(svcErr).ToGRPCStatus()
	}
	pbResp, outErr := specToPB[pb.ListTasksResponse](resp)
	if outErr != nil {
		return nil, status.Error(codes.Internal, outErr.Error())
	}
	return pbResp, nil
}

// CancelTask implements lf.a2a.v1.A2AService.CancelTask.
func (s *GRPCServer) CancelTask(ctx context.Context, req *pb.CancelTaskRequest) (*pb.Task, error) {
	idCtx, agentSlug, err := s.authenticate(ctx)
	if err != nil {
		return nil, err
	}
	if err := authorizeGRPCMutation(idCtx); err != nil {
		return nil, err
	}

	if req.GetId() == "" {
		return nil, status.Error(codes.InvalidArgument, "task id is required")
	}
	agentSlug, err = s.resolveAgentSlug(ctx, idCtx, agentSlug, req.GetId())
	if err != nil {
		return nil, err
	}

	task, svcErr := s.router.CancelTask(s.enrichedContext(ctx), idCtx, agentSlug, req.GetId())
	if svcErr != nil {
		return nil, NormalizeA2AError(svcErr).ToGRPCStatus()
	}
	pbTask, outErr := specToPB[pb.Task](task)
	if outErr != nil {
		return nil, status.Error(codes.Internal, outErr.Error())
	}
	return pbTask, nil
}

// SubscribeToTask implements lf.a2a.v1.A2AService.SubscribeToTask server streaming via StreamSubscriber.
func (s *GRPCServer) SubscribeToTask(req *pb.SubscribeToTaskRequest, stream grpc.ServerStreamingServer[pb.StreamResponse]) error {
	ctx := stream.Context()
	idCtx, agentSlug, err := s.authenticate(ctx)
	if err != nil {
		return err
	}
	if req.GetId() == "" {
		return status.Error(codes.InvalidArgument, "task id is required")
	}
	agentSlug, err = s.resolveAgentSlug(ctx, idCtx, agentSlug, req.GetId())
	if err != nil {
		return err
	}
	if s.streamSub == nil {
		return status.Error(codes.Unimplemented, "stream subscriber is not configured")
	}

	ch, svcErr := s.streamSub.SubscribeChannel(ctx, idCtx, agentSlug, req.GetId(), 0)
	if svcErr != nil {
		return NormalizeA2AError(svcErr).ToGRPCStatus()
	}

	for env := range ch {
		var pbFrame pb.StreamResponse
		if err := (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(env.StreamResponse, &pbFrame); err != nil {
			continue
		}
		if err := stream.Send(&pbFrame); err != nil {
			return err
		}
	}
	return nil
}

// CreateTaskPushNotificationConfig implements lf.a2a.v1.A2AService.CreateTaskPushNotificationConfig.
func (s *GRPCServer) CreateTaskPushNotificationConfig(ctx context.Context, req *pb.TaskPushNotificationConfig) (*pb.TaskPushNotificationConfig, error) {
	idCtx, agentSlug, err := s.authenticate(ctx)
	if err != nil {
		return nil, err
	}
	if err := authorizeGRPCMutation(idCtx); err != nil {
		return nil, err
	}

	if req.GetTaskId() == "" || req.GetUrl() == "" {
		return nil, status.Error(codes.InvalidArgument, "task_id and url are required")
	}
	agentSlug, err = s.resolveAgentSlug(ctx, idCtx, agentSlug, req.GetTaskId())
	if err != nil {
		return nil, err
	}

	specReq, convErr := pbToSpec[a2aspec.TaskPushNotificationConfig](req)
	if convErr != nil {
		return nil, status.Error(codes.InvalidArgument, convErr.Error())
	}

	cfg, svcErr := s.router.CreateTaskPushNotificationConfig(s.enrichedContext(ctx), idCtx, agentSlug, req.GetTaskId(), specReq)
	if svcErr != nil {
		return nil, NormalizeA2AError(svcErr).ToGRPCStatus()
	}
	pbCfg, outErr := specToPB[pb.TaskPushNotificationConfig](cfg)
	if outErr != nil {
		return nil, status.Error(codes.Internal, outErr.Error())
	}
	return pbCfg, nil
}

// GetTaskPushNotificationConfig implements lf.a2a.v1.A2AService.GetTaskPushNotificationConfig.
func (s *GRPCServer) GetTaskPushNotificationConfig(ctx context.Context, req *pb.GetTaskPushNotificationConfigRequest) (*pb.TaskPushNotificationConfig, error) {
	idCtx, agentSlug, err := s.authenticate(ctx)
	if err != nil {
		return nil, err
	}
	if req.GetTaskId() == "" || req.GetId() == "" {
		return nil, status.Error(codes.InvalidArgument, "task_id and id are required")
	}
	agentSlug, err = s.resolveAgentSlug(ctx, idCtx, agentSlug, req.GetTaskId())
	if err != nil {
		return nil, err
	}

	cfg, svcErr := s.router.GetTaskPushNotificationConfig(s.enrichedContext(ctx), idCtx, agentSlug, req.GetTaskId(), req.GetId())
	if svcErr != nil {
		return nil, NormalizeA2AError(svcErr).ToGRPCStatus()
	}
	pbCfg, outErr := specToPB[pb.TaskPushNotificationConfig](cfg)
	if outErr != nil {
		return nil, status.Error(codes.Internal, outErr.Error())
	}
	return pbCfg, nil
}

// ListTaskPushNotificationConfigs implements lf.a2a.v1.A2AService.ListTaskPushNotificationConfigs.
func (s *GRPCServer) ListTaskPushNotificationConfigs(ctx context.Context, req *pb.ListTaskPushNotificationConfigsRequest) (*pb.ListTaskPushNotificationConfigsResponse, error) {
	idCtx, agentSlug, err := s.authenticate(ctx)
	if err != nil {
		return nil, err
	}
	if req.GetTaskId() == "" {
		return nil, status.Error(codes.InvalidArgument, "task_id is required")
	}
	agentSlug, err = s.resolveAgentSlug(ctx, idCtx, agentSlug, req.GetTaskId())
	if err != nil {
		return nil, err
	}

	var pageSize *int32
	if req.GetPageSize() > 0 {
		ps := req.GetPageSize()
		pageSize = &ps
	}
	var pageToken *string
	if req.GetPageToken() != "" {
		pt := req.GetPageToken()
		pageToken = &pt
	}

	resp, svcErr := s.router.ListTaskPushNotificationConfigs(s.enrichedContext(ctx), idCtx, agentSlug, req.GetTaskId(), pageSize, pageToken)
	if svcErr != nil {
		return nil, NormalizeA2AError(svcErr).ToGRPCStatus()
	}
	pbResp, outErr := specToPB[pb.ListTaskPushNotificationConfigsResponse](resp)
	if outErr != nil {
		return nil, status.Error(codes.Internal, outErr.Error())
	}
	return pbResp, nil
}

// DeleteTaskPushNotificationConfig implements lf.a2a.v1.A2AService.DeleteTaskPushNotificationConfig.
func (s *GRPCServer) DeleteTaskPushNotificationConfig(ctx context.Context, req *pb.DeleteTaskPushNotificationConfigRequest) (*emptypb.Empty, error) {
	idCtx, agentSlug, err := s.authenticate(ctx)
	if err != nil {
		return nil, err
	}
	if req.GetTaskId() == "" || req.GetId() == "" {
		return nil, status.Error(codes.InvalidArgument, "task_id and id are required")
	}
	agentSlug, err = s.resolveAgentSlug(ctx, idCtx, agentSlug, req.GetTaskId())
	if err != nil {
		return nil, err
	}
	if err := authorizeGRPCMutation(idCtx); err != nil {
		return nil, err
	}

	if svcErr := s.router.DeleteTaskPushNotificationConfig(s.enrichedContext(ctx), idCtx, agentSlug, req.GetTaskId(), req.GetId()); svcErr != nil {
		return nil, NormalizeA2AError(svcErr).ToGRPCStatus()
	}
	return &emptypb.Empty{}, nil
}

// GetExtendedAgentCard implements lf.a2a.v1.A2AService.GetExtendedAgentCard.
func (s *GRPCServer) GetExtendedAgentCard(ctx context.Context, req *pb.GetExtendedAgentCardRequest) (*pb.AgentCard, error) {
	idCtx, agentSlug, err := s.authenticate(ctx)
	if err != nil {
		return nil, err
	}
	if agentSlug == "" {
		return nil, status.Error(codes.InvalidArgument, "missing agent slug (specify via x-a2a-agent-slug metadata header)")
	}
	_ = req

	card, svcErr := s.router.GetExtendedAgentCard(s.enrichedContext(ctx), idCtx, agentSlug, "")
	if svcErr != nil {
		return nil, NormalizeA2AError(svcErr).ToGRPCStatus()
	}
	pbCard, outErr := specToPB[pb.AgentCard](card)
	if outErr != nil {
		return nil, status.Error(codes.Internal, outErr.Error())
	}
	return pbCard, nil
}

func pbToSpec[T any](msg proto.Message) (*T, error) {
	b, err := protojson.MarshalOptions{UseProtoNames: false, EmitUnpopulated: false}.Marshal(msg)
	if err != nil {
		return nil, err
	}
	var out T
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func specToPB[T any, PT interface {
	*T
	proto.Message
}](v any) (*T, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var out T
	if err := (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(b, PT(&out)); err != nil {
		return nil, err
	}
	return &out, nil
}
