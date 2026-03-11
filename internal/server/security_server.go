package server

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/footprintai/containarium/internal/incus"
	"github.com/footprintai/containarium/internal/security"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// SecurityServer implements the SecurityService gRPC service
type SecurityServer struct {
	pb.UnimplementedSecurityServiceServer
	store       *security.Store
	incusClient *incus.Client
	scanner     *security.Scanner
}

// NewSecurityServer creates a new security server
func NewSecurityServer(store *security.Store, incusClient *incus.Client, scanner *security.Scanner) *SecurityServer {
	return &SecurityServer{
		store:       store,
		incusClient: incusClient,
		scanner:     scanner,
	}
}

// ListClamavReports returns ClamAV scan reports with optional filtering
func (s *SecurityServer) ListClamavReports(ctx context.Context, req *pb.ListClamavReportsRequest) (*pb.ListClamavReportsResponse, error) {
	params := security.ListParams{
		ContainerName: req.ContainerName,
		Status:        req.Status,
		From:          req.From,
		To:            req.To,
		Limit:         int(req.Limit),
		Offset:        int(req.Offset),
	}

	reports, totalCount, err := s.store.ListReports(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("failed to list reports: %w", err)
	}

	return &pb.ListClamavReportsResponse{
		Reports:    reports,
		TotalCount: totalCount,
	}, nil
}

// GetClamavSummary returns a summary of ClamAV scan status across all containers
func (s *SecurityServer) GetClamavSummary(ctx context.Context, req *pb.GetClamavSummaryRequest) (*pb.GetClamavSummaryResponse, error) {
	// Get scan summaries from DB
	summaries, err := s.store.GetContainerSummaries(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get summaries: %w", err)
	}

	// Build a map of scanned containers
	scannedMap := make(map[string]bool)
	cleanCount := int32(0)
	infectedCount := int32(0)
	for _, sum := range summaries {
		scannedMap[sum.ContainerName] = true
		if sum.LastStatus == "clean" {
			cleanCount++
		} else if sum.LastStatus == "infected" {
			infectedCount++
		}
	}

	// Get all running containers to find never-scanned ones
	neverScanned := int32(0)
	if s.incusClient != nil {
		containers, err := s.incusClient.ListContainers()
		if err == nil {
			for _, c := range containers {
				if c.Role.IsCoreRole() {
					continue
				}
				if !scannedMap[c.Name] {
					neverScanned++
					// Derive username
					username := c.Name
					if strings.HasSuffix(c.Name, "-container") {
						username = strings.TrimSuffix(c.Name, "-container")
					}
					summaries = append(summaries, &pb.ClamavContainerSummary{
						ContainerName: c.Name,
						Username:      username,
						LastStatus:    "never",
					})
				}
			}
		}
	}

	return &pb.GetClamavSummaryResponse{
		Containers:             summaries,
		TotalContainers:        int32(len(summaries)),
		CleanContainers:        cleanCount,
		InfectedContainers:     infectedCount,
		NeverScannedContainers: neverScanned,
		LastCollectionAt:       time.Now().Format(time.RFC3339),
	}, nil
}

// TriggerClamavScan enqueues scan jobs asynchronously and returns immediately
func (s *SecurityServer) TriggerClamavScan(ctx context.Context, req *pb.TriggerClamavScanRequest) (*pb.TriggerClamavScanResponse, error) {
	if s.scanner == nil {
		return nil, fmt.Errorf("security scanner is not available")
	}

	if req.ContainerName != "" {
		// Enqueue a single container scan
		username := req.ContainerName
		if strings.HasSuffix(req.ContainerName, "-container") {
			username = strings.TrimSuffix(req.ContainerName, "-container")
		}
		if _, err := s.scanner.EnqueueOne(ctx, req.ContainerName, username); err != nil {
			return nil, fmt.Errorf("failed to enqueue scan for %s: %w", req.ContainerName, err)
		}
		return &pb.TriggerClamavScanResponse{
			Message:      fmt.Sprintf("Scan queued for container %s", req.ContainerName),
			ScannedCount: 1,
		}, nil
	}

	// Enqueue scans for all running user containers
	count, err := s.scanner.EnqueueAll(ctx)
	if err != nil {
		return nil, fmt.Errorf("enqueue all failed: %w", err)
	}
	return &pb.TriggerClamavScanResponse{
		Message:      fmt.Sprintf("%d scan jobs queued", count),
		ScannedCount: int32(count),
	}, nil
}

// GetScanStatus returns the current state of the scan job queue
func (s *SecurityServer) GetScanStatus(ctx context.Context, req *pb.GetScanStatusRequest) (*pb.GetScanStatusResponse, error) {
	jobs, err := s.store.ListScanJobs(ctx, "", 100)
	if err != nil {
		return nil, fmt.Errorf("failed to list scan jobs: %w", err)
	}

	resp := &pb.GetScanStatusResponse{}
	for _, j := range jobs {
		pbJob := &pb.ScanJob{
			Id:            j.ID,
			ContainerName: j.ContainerName,
			Username:      j.Username,
			Status:        j.Status,
			RetryCount:    int32(j.RetryCount),
			ErrorMessage:  j.ErrorMessage,
			CreatedAt:     j.CreatedAt.Format(time.RFC3339),
		}
		if j.StartedAt != nil {
			pbJob.StartedAt = j.StartedAt.Format(time.RFC3339)
		}
		if j.CompletedAt != nil {
			pbJob.CompletedAt = j.CompletedAt.Format(time.RFC3339)
		}
		resp.Jobs = append(resp.Jobs, pbJob)

		switch j.Status {
		case "pending":
			resp.PendingCount++
		case "running":
			resp.RunningCount++
		case "completed":
			resp.CompletedCount++
		case "failed":
			resp.FailedCount++
		}
	}

	return resp, nil
}
