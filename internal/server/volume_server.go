package server

import (
	"context"
	"fmt"
	"log"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/pkg/core/volume"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// VolumeServer implements the gRPC VolumeService. Incus uses CephFS custom
// volumes; Kubernetes uses RWX PVCs in the authenticated tenant namespace.
type VolumeServer struct {
	pb.UnimplementedVolumeServiceServer
	backend volume.Backend
	runtime string
}

// NewVolumeServer builds the backend for the selected box runtime. If the
// runtime dependencies are unavailable it still registers and returns clear
// errors rather than exposing a partially working service.
func NewVolumeServer(runtime string) *VolumeServer {
	if runtime == RuntimeK8s {
		backend, err := newK8sBackend()
		if err != nil {
			log.Printf("[volume] Kubernetes backend unavailable (%v); shared-volume calls will error", err)
			return &VolumeServer{backend: unavailableVolumeBackend{err}, runtime: runtime}
		}
		volumeBackend, ok := backend.(volume.Backend)
		if !ok {
			err := fmt.Errorf("Kubernetes backend does not implement VolumeService")
			log.Printf("[volume] %v", err)
			return &VolumeServer{backend: unavailableVolumeBackend{err}, runtime: runtime}
		}
		return &VolumeServer{backend: volumeBackend, runtime: runtime}
	}
	runner, err := volume.NewCLIRunner()
	if err != nil {
		log.Printf("[volume] incus CLI unavailable (%v); shared-volume calls will error", err)
		return &VolumeServer{backend: volume.IncusBackend{Manager: volume.NewManager(unavailableRunner{err})}, runtime: runtime}
	}
	return &VolumeServer{backend: volume.IncusBackend{Manager: volume.NewManager(runner)}, runtime: runtime}
}

type unavailableVolumeBackend struct{ err error }

func (u unavailableVolumeBackend) SharedVolumesSupported(context.Context, string) (string, bool, string) {
	return "", false, fmt.Sprintf("shared-volume backend unavailable: %v", u.err)
}
func (u unavailableVolumeBackend) CreateVolume(context.Context, string, string, int64, string) (*volume.Volume, error) {
	return nil, u.err
}
func (u unavailableVolumeBackend) ListVolumes(context.Context, string, string) ([]volume.Volume, error) {
	return nil, u.err
}
func (u unavailableVolumeBackend) GetVolume(context.Context, string, string, string) (*volume.Volume, error) {
	return nil, u.err
}
func (u unavailableVolumeBackend) DeleteVolume(context.Context, string, string, string, bool) error {
	return u.err
}
func (u unavailableVolumeBackend) AttachVolume(context.Context, string, string, string, string, string, bool) error {
	return u.err
}
func (u unavailableVolumeBackend) DetachVolume(context.Context, string, string, string) error {
	return u.err
}

// unavailableRunner makes every Manager call fail with a stable message
// when incus isn't installed, rather than nil-panicking.
type unavailableRunner struct{ err error }

func (u unavailableRunner) Run(args ...string) (string, error) { return "", u.err }

func (s *VolumeServer) CreateVolume(ctx context.Context, req *pb.CreateVolumeRequest) (*pb.CreateVolumeResponse, error) {
	if err := auth.RequireScope(ctx, auth.ScopeVolumesWrite); err != nil {
		return nil, err
	}
	tenant, _, _ := auth.SubjectFromGRPCContext(ctx)
	v, err := s.backend.CreateVolume(ctx, tenant, req.Name, req.SizeBytes, req.Pool)
	if err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "%v", err)
	}
	log.Printf("[volume] created name=%s pool=%s size=%d", v.Name, v.Pool, v.SizeBytes)
	return &pb.CreateVolumeResponse{Volume: volumeToProto(v), Message: "volume created: " + v.Name}, nil
}

func (s *VolumeServer) ListVolumes(ctx context.Context, req *pb.ListVolumesRequest) (*pb.ListVolumesResponse, error) {
	if err := auth.RequireScope(ctx, auth.ScopeVolumesRead); err != nil {
		return nil, err
	}
	tenant, _, _ := auth.SubjectFromGRPCContext(ctx)
	pool, ok, detail := s.backend.SharedVolumesSupported(ctx, tenant)
	resp := &pb.ListVolumesResponse{SharedVolumesSupported: ok, CapabilityDetail: detail}
	if !ok {
		return resp, nil // not supported → empty list + capability detail, not an error
	}
	filter := req.Pool
	if filter == "" {
		filter = pool
	}
	vols, err := s.backend.ListVolumes(ctx, tenant, filter)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "%v", err)
	}
	for i := range vols {
		resp.Volumes = append(resp.Volumes, volumeToProto(&vols[i]))
	}
	return resp, nil
}

func (s *VolumeServer) GetVolume(ctx context.Context, req *pb.GetVolumeRequest) (*pb.GetVolumeResponse, error) {
	if err := auth.RequireScope(ctx, auth.ScopeVolumesRead); err != nil {
		return nil, err
	}
	tenant, _, _ := auth.SubjectFromGRPCContext(ctx)
	v, err := s.backend.GetVolume(ctx, tenant, req.Name, req.Pool)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "%v", err)
	}
	return &pb.GetVolumeResponse{Volume: volumeToProto(v)}, nil
}

func (s *VolumeServer) DeleteVolume(ctx context.Context, req *pb.DeleteVolumeRequest) (*pb.DeleteVolumeResponse, error) {
	if err := auth.RequireScope(ctx, auth.ScopeVolumesWrite); err != nil {
		return nil, err
	}
	tenant, _, _ := auth.SubjectFromGRPCContext(ctx)
	if err := s.backend.DeleteVolume(ctx, tenant, req.Name, req.Pool, req.Force); err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "%v", err)
	}
	log.Printf("[volume] deleted name=%s force=%t", req.Name, req.Force)
	return &pb.DeleteVolumeResponse{Message: "volume deleted: " + req.Name}, nil
}

func (s *VolumeServer) AttachVolume(ctx context.Context, req *pb.AttachVolumeRequest) (*pb.AttachVolumeResponse, error) {
	if err := auth.RequireScope(ctx, auth.ScopeVolumesWrite); err != nil {
		return nil, err
	}
	tenant, _, _ := auth.SubjectFromGRPCContext(ctx)
	authorizedTenant := req.Container
	if s.runtime == RuntimeK8s {
		authorizedTenant = tenant
	}
	if err := auth.AuthorizeTenant(ctx, authorizedTenant); err != nil {
		return nil, err
	}
	if err := s.backend.AttachVolume(ctx, tenant, req.Volume, req.Pool, req.Container, req.MountPath, req.ReadOnly); err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "%v", err)
	}
	log.Printf("[volume] attached vol=%s container=%s path=%s ro=%t", req.Volume, req.Container, req.MountPath, req.ReadOnly)
	return &pb.AttachVolumeResponse{Message: "volume attached to " + req.Container}, nil
}

func (s *VolumeServer) DetachVolume(ctx context.Context, req *pb.DetachVolumeRequest) (*pb.DetachVolumeResponse, error) {
	if err := auth.RequireScope(ctx, auth.ScopeVolumesWrite); err != nil {
		return nil, err
	}
	tenant, _, _ := auth.SubjectFromGRPCContext(ctx)
	authorizedTenant := req.Container
	if s.runtime == RuntimeK8s {
		authorizedTenant = tenant
	}
	if err := auth.AuthorizeTenant(ctx, authorizedTenant); err != nil {
		return nil, err
	}
	if err := s.backend.DetachVolume(ctx, tenant, req.Volume, req.Container); err != nil {
		return nil, status.Errorf(codes.Internal, "%v", err)
	}
	log.Printf("[volume] detached vol=%s container=%s", req.Volume, req.Container)
	return &pb.DetachVolumeResponse{Message: "volume detached from " + req.Container}, nil
}

func volumeToProto(v *volume.Volume) *pb.Volume {
	out := &pb.Volume{
		Name:        v.Name,
		Pool:        v.Pool,
		SizeBytes:   v.SizeBytes,
		ContentType: v.ContentType,
	}
	for _, a := range v.Attachments {
		out.Attachments = append(out.Attachments, &pb.VolumeAttachment{
			Container: a.Container,
			MountPath: a.MountPath,
			ReadOnly:  a.ReadOnly,
		})
	}
	return out
}
