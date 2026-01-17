package server

import (
	"context"
	"fmt"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/footprintai/containarium/internal/app"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// AppServer implements the gRPC AppService
type AppServer struct {
	pb.UnimplementedAppServiceServer
	manager *app.Manager
	store   *app.Store
}

// NewAppServer creates a new app server
func NewAppServer(manager *app.Manager, store *app.Store) *AppServer {
	return &AppServer{
		manager: manager,
		store:   store,
	}
}

// DeployApp deploys a new application or updates an existing one
func (s *AppServer) DeployApp(ctx context.Context, req *pb.DeployAppRequest) (*pb.DeployAppResponse, error) {
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

	// Deploy the app
	deployedApp, detectedLang, err := s.manager.DeployApp(ctx, req)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "deployment failed: %v", err)
	}

	return &pb.DeployAppResponse{
		App:              deployedApp,
		Message:          fmt.Sprintf("Application %s deployed successfully at https://%s", req.AppName, deployedApp.FullDomain),
		DetectedLanguage: detectedLang,
	}, nil
}

// ListApps lists all applications for a user
func (s *AppServer) ListApps(ctx context.Context, req *pb.ListAppsRequest) (*pb.ListAppsResponse, error) {
	apps, err := s.store.List(ctx, req.Username, req.StateFilter)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to list apps: %v", err)
	}

	count, err := s.store.Count(ctx, req.Username, req.StateFilter)
	if err != nil {
		count = int32(len(apps))
	}

	return &pb.ListAppsResponse{
		Apps:       apps,
		TotalCount: count,
	}, nil
}

// GetApp gets details for a specific application
func (s *AppServer) GetApp(ctx context.Context, req *pb.GetAppRequest) (*pb.GetAppResponse, error) {
	if req.Username == "" {
		return nil, status.Errorf(codes.InvalidArgument, "username is required")
	}
	if req.AppName == "" {
		return nil, status.Errorf(codes.InvalidArgument, "app_name is required")
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
	if req.Username == "" {
		return nil, status.Errorf(codes.InvalidArgument, "username is required")
	}
	if req.AppName == "" {
		return nil, status.Errorf(codes.InvalidArgument, "app_name is required")
	}

	stoppedApp, err := s.manager.StopApp(ctx, req.Username, req.AppName)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to stop app: %v", err)
	}

	return &pb.StopAppResponse{
		App:     stoppedApp,
		Message: fmt.Sprintf("Application %s stopped", req.AppName),
	}, nil
}

// StartApp starts a stopped application
func (s *AppServer) StartApp(ctx context.Context, req *pb.StartAppRequest) (*pb.StartAppResponse, error) {
	if req.Username == "" {
		return nil, status.Errorf(codes.InvalidArgument, "username is required")
	}
	if req.AppName == "" {
		return nil, status.Errorf(codes.InvalidArgument, "app_name is required")
	}

	startedApp, err := s.manager.StartApp(ctx, req.Username, req.AppName)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to start app: %v", err)
	}

	return &pb.StartAppResponse{
		App:     startedApp,
		Message: fmt.Sprintf("Application %s started", req.AppName),
	}, nil
}

// RestartApp restarts an application
func (s *AppServer) RestartApp(ctx context.Context, req *pb.RestartAppRequest) (*pb.RestartAppResponse, error) {
	if req.Username == "" {
		return nil, status.Errorf(codes.InvalidArgument, "username is required")
	}
	if req.AppName == "" {
		return nil, status.Errorf(codes.InvalidArgument, "app_name is required")
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
	if req.Username == "" {
		return nil, status.Errorf(codes.InvalidArgument, "username is required")
	}
	if req.AppName == "" {
		return nil, status.Errorf(codes.InvalidArgument, "app_name is required")
	}

	err := s.manager.DeleteApp(ctx, req.Username, req.AppName, req.RemoveData)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to delete app: %v", err)
	}

	return &pb.DeleteAppResponse{
		Message: fmt.Sprintf("Application %s deleted", req.AppName),
	}, nil
}

// GetAppLogs gets application logs (streaming)
func (s *AppServer) GetAppLogs(req *pb.GetAppLogsRequest, stream pb.AppService_GetAppLogsServer) error {
	if req.Username == "" {
		return status.Errorf(codes.InvalidArgument, "username is required")
	}
	if req.AppName == "" {
		return status.Errorf(codes.InvalidArgument, "app_name is required")
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
