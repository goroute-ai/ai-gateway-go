package a2a

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/goroute-ai/ai-gateway-go/internal/a2a/pb"
	"github.com/goroute-ai/ai-gateway-go/internal/auth"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/redis/go-redis/v9"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

// GRPCServer implements the Linux Foundation lf.a2a.v1.A2AServiceServer gRPC interface.
type GRPCServer struct {
	pb.UnimplementedA2AServiceServer
	router  *RouterService
	authSvc *auth.Service
	rbac    *auth.RBACEngine
}

// NewGRPCServer creates a new A2A gRPC server instance.
func NewGRPCServer(router *RouterService, authSvc *auth.Service, rbac *auth.RBACEngine) *GRPCServer {
	return &GRPCServer{
		router:  router,
		authSvc: authSvc,
		rbac:    rbac,
	}
}

// Register registers this gRPC service on the specified gRPC server.
func (s *GRPCServer) Register(srv grpc.ServiceRegistrar) {
	pb.RegisterA2AServiceServer(srv, s)
}

// authenticate extracts the VirtualKey Bearer token and agent slug from gRPC metadata.
func (s *GRPCServer) authenticate(ctx context.Context) (*domain.IdentityContext, string, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, "", status.Error(codes.Unauthenticated, "missing grpc metadata")
	}

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

	idCtx, err := s.authSvc.AuthenticateVirtualKey(ctx, rawToken)
	if err != nil {
		return nil, "", status.Error(codes.Unauthenticated, "invalid virtual key: "+err.Error())
	}

	agentSlug := ""
	slugHeaders := md.Get("x-a2a-agent-slug")
	if len(slugHeaders) > 0 {
		agentSlug = strings.TrimSpace(slugHeaders[0])
	}

	return idCtx, agentSlug, nil
}

func (s *GRPCServer) resolveAgentSlug(ctx context.Context, idCtx *domain.IdentityContext, agentSlug, taskID string) (string, error) {
	if agentSlug != "" {
		return agentSlug, nil
	}
	if taskID != "" && s.router != nil && s.router.repo != nil {
		task, err := s.router.repo.GetA2ATask(ctx, taskID)
		if err == nil && task != nil {
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

	if agentSlug == "" && req.Message != nil {
		if req.Message.Metadata != nil {
			if val, ok := req.Message.Metadata.Fields["agent_slug"]; ok {
				agentSlug = val.GetStringValue()
			}
		}
		if agentSlug == "" && req.Message.TaskId != "" {
			agentSlug, _ = s.resolveAgentSlug(ctx, idCtx, "", req.Message.TaskId)
		}
	}
	if agentSlug == "" {
		return nil, status.Error(codes.InvalidArgument, "missing agent slug (specify via x-a2a-agent-slug metadata or message.metadata.agent_slug)")
	}

	if s.rbac != nil {
		if err := s.rbac.AuthorizeA2AAgent(idCtx, agentSlug); err != nil {
			return nil, status.Error(codes.PermissionDenied, "unauthorized access to agent "+agentSlug)
		}
	}

	resp, err := s.router.SendMessage(ctx, idCtx, agentSlug, req)
	if err != nil {
		return nil, status.Error(codes.Internal, "a2a send failed: "+err.Error())
	}

	return resp, nil
}

// GetTask implements lf.a2a.v1.A2AService.GetTask.
func (s *GRPCServer) GetTask(ctx context.Context, req *pb.GetTaskRequest) (*pb.Task, error) {
	idCtx, agentSlug, err := s.authenticate(ctx)
	if err != nil {
		return nil, err
	}

	if req.Id == "" {
		return nil, status.Error(codes.InvalidArgument, "task id is required")
	}

	agentSlug, err = s.resolveAgentSlug(ctx, idCtx, agentSlug, req.Id)
	if err != nil {
		return nil, err
	}

	task, err := s.router.GetTask(ctx, idCtx, agentSlug, req.Id)
	if err != nil {
		var a2aErr *A2AError
		if errors.As(err, &a2aErr) && a2aErr.Code == CodeTaskNotFound {
			return nil, status.Error(codes.NotFound, "task not found")
		}
		return nil, status.Error(codes.Internal, err.Error())
	}

	return task, nil
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

	resp, err := s.router.ListTasks(ctx, idCtx, agentSlug, req)
	if err != nil {
		var a2aErr *A2AError
		if errors.As(err, &a2aErr) && a2aErr.Code == CodeTaskNotFound {
			return nil, status.Error(codes.NotFound, a2aErr.Message)
		}
		return nil, status.Error(codes.Internal, err.Error())
	}

	return resp, nil
}

// CancelTask implements lf.a2a.v1.A2AService.CancelTask.
func (s *GRPCServer) CancelTask(ctx context.Context, req *pb.CancelTaskRequest) (*pb.Task, error) {
	idCtx, agentSlug, err := s.authenticate(ctx)
	if err != nil {
		return nil, err
	}

	if req.Id == "" {
		return nil, status.Error(codes.InvalidArgument, "task id is required")
	}

	agentSlug, err = s.resolveAgentSlug(ctx, idCtx, agentSlug, req.Id)
	if err != nil {
		return nil, err
	}

	task, err := s.router.CancelTask(ctx, idCtx, agentSlug, req.Id)
	if err != nil {
		var a2aErr *A2AError
		if errors.As(err, &a2aErr) && a2aErr.Code == CodeTaskNotFound {
			return nil, status.Error(codes.NotFound, "task not found")
		}
		return nil, status.Error(codes.Internal, err.Error())
	}

	return task, nil
}

// SubscribeToTask implements lf.a2a.v1.A2AService.SubscribeToTask server streaming.
func (s *GRPCServer) SubscribeToTask(req *pb.SubscribeToTaskRequest, stream grpc.ServerStreamingServer[pb.StreamResponse]) error {
	ctx := stream.Context()
	idCtx, agentSlug, err := s.authenticate(ctx)
	if err != nil {
		return err
	}

	if req.Id == "" {
		return status.Error(codes.InvalidArgument, "task id is required")
	}

	agentSlug, err = s.resolveAgentSlug(ctx, idCtx, agentSlug, req.Id)
	if err != nil {
		return err
	}

	// Verify task existence & access
	task, err := s.router.GetTask(ctx, idCtx, agentSlug, req.Id)
	if err != nil {
		return status.Error(codes.NotFound, "task not found")
	}

	// If already in terminal state, return error
	if task.Status != nil && (task.Status.State == pb.TaskState_TASK_STATE_COMPLETED ||
		task.Status.State == pb.TaskState_TASK_STATE_FAILED ||
		task.Status.State == pb.TaskState_TASK_STATE_CANCELED ||
		task.Status.State == pb.TaskState_TASK_STATE_REJECTED) {
		return status.Error(codes.FailedPrecondition, "cannot subscribe to task in terminal state")
	}

	// Backfill historical events
	events, err := s.router.repo.ListA2ATaskEvents(ctx, req.Id, 0, 100)
	if err == nil {
		for _, ev := range events {
			var streamResp *pb.StreamResponse
			switch ev.EventType {
			case "status":
				var statusEv pb.TaskStatusUpdateEvent
				if err := json.Unmarshal([]byte(ev.PayloadJSON), &statusEv); err == nil {
					streamResp = &pb.StreamResponse{
						Payload: &pb.StreamResponse_StatusUpdate{StatusUpdate: &statusEv},
					}
				} else {
					streamResp = &pb.StreamResponse{
						Payload: &pb.StreamResponse_StatusUpdate{
							StatusUpdate: &pb.TaskStatusUpdateEvent{TaskId: ev.TaskID},
						},
					}
				}
			case "artifact":
				var artEv pb.TaskArtifactUpdateEvent
				if err := json.Unmarshal([]byte(ev.PayloadJSON), &artEv); err == nil {
					streamResp = &pb.StreamResponse{
						Payload: &pb.StreamResponse_ArtifactUpdate{ArtifactUpdate: &artEv},
					}
				}
			default:
				var msg pb.Message
				if err := json.Unmarshal([]byte(ev.PayloadJSON), &msg); err == nil {
					streamResp = &pb.StreamResponse{
						Payload: &pb.StreamResponse_Message{Message: &msg},
					}
				} else {
					streamResp = &pb.StreamResponse{
						Payload: &pb.StreamResponse_Message{
							Message: &pb.Message{
								TaskId: ev.TaskID,
								Role:   pb.Role_ROLE_AGENT,
								Parts:  []*pb.Part{{Content: &pb.Part_Text{Text: ev.PayloadJSON}}},
							},
						},
					}
				}
			}
			if streamResp != nil {
				if err := stream.Send(streamResp); err != nil {
					return err
				}
			}
		}
	}

	// Subscribe to live Redis channel if available
	if s.router.redisFabric != nil {
		channel := fmt.Sprintf("gw:a2a:events:%s", req.Id)
		liveEventCh := make(chan string, 32)
		subCtx, cancelSub := context.WithCancel(ctx)
		defer cancelSub()

		go func() {
			_, _ = s.router.redisFabric.Execute(func(rdb redis.UniversalClient) (any, error) {
				pubsub := rdb.Subscribe(subCtx, channel)
				defer pubsub.Close()
				for {
					msg, err := pubsub.ReceiveMessage(subCtx)
					if err != nil {
						return nil, err
					}
					if msg != nil {
						select {
						case liveEventCh <- msg.Payload:
						case <-subCtx.Done():
							return nil, nil
						}
					}
				}
			})
		}()

		for {
			select {
			case <-ctx.Done():
				return nil
			case payload := <-liveEventCh:
				var streamResp pb.StreamResponse
				if err := json.Unmarshal([]byte(payload), &streamResp); err != nil {
					streamResp = pb.StreamResponse{
						Payload: &pb.StreamResponse_Message{
							Message: &pb.Message{
								TaskId: req.Id,
								Role:   pb.Role_ROLE_AGENT,
								Parts:  []*pb.Part{{Content: &pb.Part_Text{Text: payload}}},
							},
						},
					}
				}
				if err := stream.Send(&streamResp); err != nil {
					return err
				}
			}
		}
	}

	return nil
}

// CreateTaskPushNotificationConfig implements lf.a2a.v1.A2AService.CreateTaskPushNotificationConfig.
func (s *GRPCServer) CreateTaskPushNotificationConfig(ctx context.Context, req *pb.TaskPushNotificationConfig) (*pb.TaskPushNotificationConfig, error) {
	idCtx, _, err := s.authenticate(ctx)
	if err != nil {
		return nil, err
	}

	if req.TaskId == "" || req.Url == "" {
		return nil, status.Error(codes.InvalidArgument, "task_id and url are required")
	}

	agentSlug, err := s.resolveAgentSlug(ctx, idCtx, "", req.TaskId)
	if err != nil {
		return nil, err
	}

	// Check task access
	if _, err := s.router.GetTask(ctx, idCtx, agentSlug, req.TaskId); err != nil {
		return nil, status.Error(codes.NotFound, "task not found")
	}

	cfg := &domain.A2APushNotificationConfig{
		ID:        req.Id,
		TaskID:    req.TaskId,
		TargetURL: req.Url,
	}
	if cfg.ID == "" {
		cfg.ID = "push_" + req.TaskId
	}
	if err := s.router.repo.SetA2APushNotificationConfig(ctx, cfg); err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	req.Id = cfg.ID
	return req, nil
}

// GetTaskPushNotificationConfig implements lf.a2a.v1.A2AService.GetTaskPushNotificationConfig.
func (s *GRPCServer) GetTaskPushNotificationConfig(ctx context.Context, req *pb.GetTaskPushNotificationConfigRequest) (*pb.TaskPushNotificationConfig, error) {
	idCtx, _, err := s.authenticate(ctx)
	if err != nil {
		return nil, err
	}

	if req.TaskId == "" {
		return nil, status.Error(codes.InvalidArgument, "task_id is required")
	}

	agentSlug, err := s.resolveAgentSlug(ctx, idCtx, "", req.TaskId)
	if err != nil {
		return nil, err
	}

	// Check task access
	if _, err := s.router.GetTask(ctx, idCtx, agentSlug, req.TaskId); err != nil {
		return nil, status.Error(codes.NotFound, "task not found")
	}

	cfg, err := s.router.repo.GetA2APushNotificationConfig(ctx, req.TaskId)
	if err != nil {
		return nil, status.Error(codes.NotFound, "push config not found")
	}

	return &pb.TaskPushNotificationConfig{
		Id:     cfg.ID,
		TaskId: cfg.TaskID,
		Url:    cfg.TargetURL,
	}, nil
}

// DeleteTaskPushNotificationConfig implements lf.a2a.v1.A2AService.DeleteTaskPushNotificationConfig.
func (s *GRPCServer) DeleteTaskPushNotificationConfig(ctx context.Context, req *pb.DeleteTaskPushNotificationConfigRequest) (*emptypb.Empty, error) {
	_, _, err := s.authenticate(ctx)
	if err != nil {
		return nil, err
	}

	return &emptypb.Empty{}, nil
}
