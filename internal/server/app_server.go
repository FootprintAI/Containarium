package server

import (
	"context"
	"fmt"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/footprintai/containarium/internal/app"
	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/internal/events"
	"github.com/footprintai/containarium/internal/safecast"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// AppServer implements the gRPC AppService
type AppServer struct {
	pb.UnimplementedAppServiceServer
	manager *app.Manager
	store   app.AppStore
	emitter *events.Emitter
}

// NewAppServer creates a new app server
func NewAppServer(manager *app.Manager, store app.AppStore) *AppServer {
	return &AppServer{
		manager: manager,
		store:   store,
		emitter: events.NewEmitter(events.GetBus()),
	}
}

// isDisabled returns true when app hosting is not configured
func (s *AppServer) isDisabled() bool {
	return s.store == nil || s.manager == nil
}

// DeployApp deploys a new application or updates an existing one
func (s *AppServer) DeployApp(ctx context.Context, req *pb.DeployAppRequest) (*pb.DeployAppResponse, error) {
	if err := auth.RequireScope(ctx, auth.ScopeContainersWrite); err != nil {
		return nil, err
	}
	if s.isDisabled() {
		return nil, status.Errorf(codes.Unavailable, "app hosting is not enabled")
	}
	// Validate request
	if req.Username == "" {
		return nil, status.Errorf(codes.InvalidArgument, "username is required")
	}
	if req.AppName == "" {
		return nil, status.Errorf(codes.InvalidArgument, "app_name is required")
	}
	if len(req.SourceTarball) == 0 {
		return nil, status.Errorf(codes.InvalidArgument, "source_tarball is required")
	}
	if err := auth.AuthorizeTenant(ctx, req.Username); err != nil {
		return nil, err
	}

	// Deploy the app
	deployedApp, detectedLang, err := s.manager.DeployApp(ctx, req)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "deployment failed: %v", err)
	}

	// Emit app deployed event
	s.emitter.EmitAppDeployed(deployedApp)

	return &pb.DeployAppResponse{
		App:              deployedApp,
		Message:          fmt.Sprintf("Application %s deployed successfully at https://%s", req.AppName, deployedApp.FullDomain),
		DetectedLanguage: detectedLang,
	}, nil
}

// ListApps lists all applications for a user
func (s *AppServer) ListApps(ctx context.Context, req *pb.ListAppsRequest) (*pb.ListAppsResponse, error) {
	if err := auth.RequireScope(ctx, auth.ScopeContainersRead); err != nil {
		return nil, err
	}
	if s.isDisabled() {
		return &pb.ListAppsResponse{Apps: nil, TotalCount: 0}, nil
	}
	// Tenant isolation: non-admin → list only your own. Empty username
	// for a non-admin is rewritten to the subject.
	subject, roles, ok := auth.SubjectFromGRPCContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "no authenticated subject")
	}
	if !auth.HasRole(roles, auth.RoleAdmin) {
		if req.Username != "" && req.Username != subject {
			return nil, status.Error(codes.PermissionDenied, "not authorized for this tenant")
		}
		req.Username = subject
	}
	apps, err := s.store.List(ctx, req.Username, req.StateFilter)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to list apps: %v", err)
	}

	count, err := s.store.Count(ctx, req.Username, req.StateFilter)
	if err != nil {
		count = safecast.I32(len(apps))
	}

	return &pb.ListAppsResponse{
		Apps:       apps,
		TotalCount: count,
	}, nil
}

// GetApp gets details for a specific application
func (s *AppServer) GetApp(ctx context.Context, req *pb.GetAppRequest) (*pb.GetAppResponse, error) {
	if err := auth.RequireScope(ctx, auth.ScopeContainersRead); err != nil {
		return nil, err
	}
	if s.isDisabled() {
		return nil, status.Errorf(codes.Unavailable, "app hosting is not enabled")
	}
	if req.Username == "" {
		return nil, status.Errorf(codes.InvalidArgument, "username is required")
	}
	if req.AppName == "" {
		return nil, status.Errorf(codes.InvalidArgument, "app_name is required")
	}
	if err := auth.AuthorizeTenant(ctx, req.Username); err != nil {
		return nil, err
	}

	appInfo, err := s.store.GetByName(ctx, req.Username, req.AppName)
	if err != nil {
		if err == app.ErrNotFound {
			return nil, status.Errorf(codes.NotFound, "app not found: %s/%s", req.Username, req.AppName)
		}
		return nil, status.Errorf(codes.Internal, "failed to get app: %v", err)
	}

	return &pb.GetAppResponse{
		App: appInfo,
	}, nil
}

// StopApp stops a running application
func (s *AppServer) StopApp(ctx context.Context, req *pb.StopAppRequest) (*pb.StopAppResponse, error) {
	if err := auth.RequireScope(ctx, auth.ScopeContainersWrite); err != nil {
		return nil, err
	}
	if s.isDisabled() {
		return nil, status.Errorf(codes.Unavailable, "app hosting is not enabled")
	}
	if req.Username == "" {
		return nil, status.Errorf(codes.InvalidArgument, "username is required")
	}
	if req.AppName == "" {
		return nil, status.Errorf(codes.InvalidArgument, "app_name is required")
	}
	if err := auth.AuthorizeTenant(ctx, req.Username); err != nil {
		return nil, err
	}

	stoppedApp, err := s.manager.StopApp(ctx, req.Username, req.AppName)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to stop app: %v", err)
	}

	// Emit app stopped event
	s.emitter.EmitAppStopped(stoppedApp)

	return &pb.StopAppResponse{
		App:     stoppedApp,
		Message: fmt.Sprintf("Application %s stopped", req.AppName),
	}, nil
}

// StartApp starts a stopped application
func (s *AppServer) StartApp(ctx context.Context, req *pb.StartAppRequest) (*pb.StartAppResponse, error) {
	if err := auth.RequireScope(ctx, auth.ScopeContainersWrite); err != nil {
		return nil, err
	}
	if s.isDisabled() {
		return nil, status.Errorf(codes.Unavailable, "app hosting is not enabled")
	}
	if req.Username == "" {
		return nil, status.Errorf(codes.InvalidArgument, "username is required")
	}
	if req.AppName == "" {
		return nil, status.Errorf(codes.InvalidArgument, "app_name is required")
	}
	if err := auth.AuthorizeTenant(ctx, req.Username); err != nil {
		return nil, err
	}

	startedApp, err := s.manager.StartApp(ctx, req.Username, req.AppName)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to start app: %v", err)
	}

	// Emit app started event
	s.emitter.EmitAppStarted(startedApp)

	return &pb.StartAppResponse{
		App:     startedApp,
		Message: fmt.Sprintf("Application %s started", req.AppName),
	}, nil
}

// RestartApp restarts an application
func (s *AppServer) RestartApp(ctx context.Context, req *pb.RestartAppRequest) (*pb.RestartAppResponse, error) {
	if err := auth.RequireScope(ctx, auth.ScopeContainersWrite); err != nil {
		return nil, err
	}
	if s.isDisabled() {
		return nil, status.Errorf(codes.Unavailable, "app hosting is not enabled")
	}
	if req.Username == "" {
		return nil, status.Errorf(codes.InvalidArgument, "username is required")
	}
	if req.AppName == "" {
		return nil, status.Errorf(codes.InvalidArgument, "app_name is required")
	}
	if err := auth.AuthorizeTenant(ctx, req.Username); err != nil {
		return nil, err
	}

	restartedApp, err := s.manager.RestartApp(ctx, req.Username, req.AppName)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to restart app: %v", err)
	}

	return &pb.RestartAppResponse{
		App:     restartedApp,
		Message: fmt.Sprintf("Application %s restarted", req.AppName),
	}, nil
}

// DeleteApp deletes an application
func (s *AppServer) DeleteApp(ctx context.Context, req *pb.DeleteAppRequest) (*pb.DeleteAppResponse, error) {
	if err := auth.RequireScope(ctx, auth.ScopeContainersWrite); err != nil {
		return nil, err
	}
	if s.isDisabled() {
		return nil, status.Errorf(codes.Unavailable, "app hosting is not enabled")
	}
	if req.Username == "" {
		return nil, status.Errorf(codes.InvalidArgument, "username is required")
	}
	if req.AppName == "" {
		return nil, status.Errorf(codes.InvalidArgument, "app_name is required")
	}
	if err := auth.AuthorizeTenant(ctx, req.Username); err != nil {
		return nil, err
	}

	// Get app ID before deletion for event
	appInfo, _ := s.store.GetByName(ctx, req.Username, req.AppName)
	appID := ""
	if appInfo != nil {
		appID = appInfo.Id
	}

	err := s.manager.DeleteApp(ctx, req.Username, req.AppName, req.RemoveData)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to delete app: %v", err)
	}

	// Emit app deleted event
	if appID != "" {
		s.emitter.EmitAppDeleted(appID)
	}

	return &pb.DeleteAppResponse{
		Message: fmt.Sprintf("Application %s deleted", req.AppName),
	}, nil
}

// GetAppLogs gets application logs (streaming)
func (s *AppServer) GetAppLogs(req *pb.GetAppLogsRequest, stream pb.AppService_GetAppLogsServer) error {
	ctx := stream.Context()
	if err := auth.RequireScope(ctx, auth.ScopeContainersRead); err != nil {
		return err
	}
	if s.isDisabled() {
		return status.Errorf(codes.Unavailable, "app hosting is not enabled")
	}
	if req.Username == "" {
		return status.Errorf(codes.InvalidArgument, "username is required")
	}
	if req.AppName == "" {
		return status.Errorf(codes.InvalidArgument, "app_name is required")
	}
	if err := auth.AuthorizeTenant(ctx, req.Username); err != nil {
		return err
	}

	tailLines := req.TailLines
	if tailLines == 0 {
		tailLines = 100
	}

	// Get logs from manager
	logs, err := s.manager.GetLogs(stream.Context(), req.Username, req.AppName, tailLines, req.Follow)
	if err != nil {
		return status.Errorf(codes.Internal, "failed to get logs: %v", err)
	}

	// Send logs
	resp := &pb.GetAppLogsResponse{
		LogLines:  logs,
		Timestamp: timestamppb.Now(),
	}

	if err := stream.Send(resp); err != nil {
		return status.Errorf(codes.Internal, "failed to send logs: %v", err)
	}

	// TODO: Implement follow mode with streaming
	// For now, we just return a single batch of logs

	return nil
}
