package server

import (
	"context"
	"log"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/pkg/core/volume"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// VolumeServer implements the gRPC VolumeService — shared, multi-writer
// CephFS volumes (#384). Capability-gated: create/attach are rejected
// unless the host has a cephfs storage pool.
//
// NOT end-to-end verified: exercising the real path needs an Incus cluster
// on Ceph. The command construction + capability detection are unit-tested
// in pkg/core/volume; the orchestration here is thin.
type VolumeServer struct {
	pb.UnimplementedVolumeServiceServer
	mgr *volume.Manager
}

// NewVolumeServer builds the server. If `incus` is absent the server still
// registers but every call returns a clear error (no silent partial
// surface) — matches how the backup server degrades without gcloud.
func NewVolumeServer() *VolumeServer {
	runner, err := volume.NewCLIRunner()
	if err != nil {
		log.Printf("[volume] incus CLI unavailable (%v); shared-volume calls will error", err)
		return &VolumeServer{mgr: volume.NewManager(unavailableRunner{err})}
	}
	return &VolumeServer{mgr: volume.NewManager(runner)}
}

// unavailableRunner makes every Manager call fail with a stable message
// when incus isn't installed, rather than nil-panicking.
type unavailableRunner struct{ err error }

func (u unavailableRunner) Run(args ...string) (string, error) { return "", u.err }

func (s *VolumeServer) CreateVolume(ctx context.Context, req *pb.CreateVolumeRequest) (*pb.CreateVolumeResponse, error) {
	if err := auth.RequireScope(ctx, auth.ScopeVolumesWrite); err != nil {
		return nil, err
	}
	v, err := s.mgr.Create(req.Name, req.SizeBytes, req.Pool)
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
	pool, ok, detail := s.mgr.SharedVolumesSupported()
	resp := &pb.ListVolumesResponse{SharedVolumesSupported: ok, CapabilityDetail: detail}
	if !ok {
		return resp, nil // not supported → empty list + capability detail, not an error
	}
	filter := req.Pool
	if filter == "" {
		filter = pool
	}
	vols, err := s.mgr.List(filter)
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
	v, err := s.mgr.Get(req.Name, req.Pool)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "%v", err)
	}
	return &pb.GetVolumeResponse{Volume: volumeToProto(v)}, nil
}

func (s *VolumeServer) DeleteVolume(ctx context.Context, req *pb.DeleteVolumeRequest) (*pb.DeleteVolumeResponse, error) {
	if err := auth.RequireScope(ctx, auth.ScopeVolumesWrite); err != nil {
		return nil, err
	}
	if err := s.mgr.Delete(req.Name, req.Pool, req.Force); err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "%v", err)
	}
	log.Printf("[volume] deleted name=%s force=%t", req.Name, req.Force)
	return &pb.DeleteVolumeResponse{Message: "volume deleted: " + req.Name}, nil
}

func (s *VolumeServer) AttachVolume(ctx context.Context, req *pb.AttachVolumeRequest) (*pb.AttachVolumeResponse, error) {
	if err := auth.RequireScope(ctx, auth.ScopeVolumesWrite); err != nil {
		return nil, err
	}
	if err := auth.AuthorizeTenant(ctx, req.Container); err != nil {
		return nil, err
	}
	if err := s.mgr.Attach(req.Volume, req.Pool, req.Container, req.MountPath, req.ReadOnly); err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "%v", err)
	}
	log.Printf("[volume] attached vol=%s container=%s path=%s ro=%t", req.Volume, req.Container, req.MountPath, req.ReadOnly)
	return &pb.AttachVolumeResponse{Message: "volume attached to " + req.Container}, nil
}

func (s *VolumeServer) DetachVolume(ctx context.Context, req *pb.DetachVolumeRequest) (*pb.DetachVolumeResponse, error) {
	if err := auth.RequireScope(ctx, auth.ScopeVolumesWrite); err != nil {
		return nil, err
	}
	if err := auth.AuthorizeTenant(ctx, req.Container); err != nil {
		return nil, err
	}
	if err := s.mgr.Detach(req.Volume, req.Container); err != nil {
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
