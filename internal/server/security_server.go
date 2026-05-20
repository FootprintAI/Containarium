package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/footprintai/containarium/internal/auth"
	"github.com/footprintai/containarium/internal/security"
	"github.com/footprintai/containarium/pkg/core/incus"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

// SecurityServer implements the SecurityService gRPC service
type SecurityServer struct {
	pb.UnimplementedSecurityServiceServer
	store          *security.Store
	incusClient    *incus.Client
	scanner        *security.Scanner
	peerPool       *PeerPool
	localBackendID string
}

// SetPeerPool sets the peer pool for including peer containers in security summaries.
func (s *SecurityServer) SetPeerPool(pool *PeerPool) {
	s.peerPool = pool
	if pool != nil {
		s.localBackendID = pool.LocalBackendID()
	}
}

// NewSecurityServer creates a new security server
func NewSecurityServer(store *security.Store, incusClient *incus.Client, scanner *security.Scanner) *SecurityServer {
	return &SecurityServer{
		store:       store,
		incusClient: incusClient,
		scanner:     scanner,
	}
}

// ListClamavReports returns ClamAV scan reports with optional filtering.
// Phase 1.4 — when ContainerName is set, tenant authz via the
// owner derivation; when blank, the listing would cover all
// containers, so require admin.
func (s *SecurityServer) ListClamavReports(ctx context.Context, req *pb.ListClamavReportsRequest) (*pb.ListClamavReportsResponse, error) {
	if err := auth.RequireScope(ctx, auth.ScopeSecurityRead); err != nil {
		return nil, err
	}
	if req.ContainerName == "" {
		if err := auth.RequireRole(ctx, auth.RoleAdmin); err != nil {
			return nil, err
		}
	} else {
		if err := auth.AuthorizeContainerAccess(ctx, req.ContainerName); err != nil {
			return nil, err
		}
	}
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

	// Tag local reports with backend_id
	for _, r := range reports {
		if r.BackendId == "" {
			r.BackendId = s.localBackendID
		}
	}

	// Merge reports from peers
	if s.peerPool != nil {
		authToken := extractAuthToken(ctx)
		peerReports := s.fetchPeerReports(authToken, req)
		reports = append(reports, peerReports...)
		totalCount += int32(len(peerReports)) // #nosec G115 -- value bounded by container/scan count
	}

	return &pb.ListClamavReportsResponse{
		Reports:    reports,
		TotalCount: totalCount,
	}, nil
}

// fetchPeerReports fetches ClamAV reports from all peers in parallel.
func (s *SecurityServer) fetchPeerReports(authToken string, req *pb.ListClamavReportsRequest) []*pb.ClamavReport {
	peers := s.peerPool.Peers()
	if len(peers) == 0 {
		return nil
	}

	// Build query params
	var qp []string
	if req.ContainerName != "" {
		qp = append(qp, "container_name="+req.ContainerName)
	}
	if req.Status != "" {
		qp = append(qp, "status="+req.Status)
	}
	if req.From != "" {
		qp = append(qp, "from="+req.From)
	}
	if req.To != "" {
		qp = append(qp, "to="+req.To)
	}
	if req.Limit > 0 {
		qp = append(qp, fmt.Sprintf("limit=%d", req.Limit))
	}
	queryParams := strings.Join(qp, "&")

	type result struct {
		reports []*pb.ClamavReport
	}

	var mu sync.Mutex
	var wg sync.WaitGroup
	var all []*pb.ClamavReport

	for _, peer := range peers {
		if !peer.Healthy {
			continue
		}
		wg.Add(1)
		go func(pc *PeerClient) {
			defer wg.Done()
			body, err := pc.ForwardSecurityReports(authToken, queryParams)
			if err != nil {
				log.Printf("[security] failed to fetch reports from peer %s: %v", pc.ID, err)
				return
			}
			var resp pb.ListClamavReportsResponse
			if err := protojson.Unmarshal(body, &resp); err != nil {
				log.Printf("[security] failed to parse reports from peer %s: %v", pc.ID, err)
				return
			}
			// Tag with backend_id
			for _, r := range resp.Reports {
				if r.BackendId == "" {
					r.BackendId = pc.ID
				}
			}
			mu.Lock()
			all = append(all, resp.Reports...)
			mu.Unlock()
		}(peer)
	}
	wg.Wait()
	return all
}

// GetClamavSummary returns a summary of ClamAV scan status across all containers.
// Admin-only — cluster-wide infection counts leak posture data and
// list every container by name.
func (s *SecurityServer) GetClamavSummary(ctx context.Context, req *pb.GetClamavSummaryRequest) (*pb.GetClamavSummaryResponse, error) {
	if err := auth.RequireScope(ctx, auth.ScopeSecurityRead); err != nil {
		return nil, err
	}
	if err := auth.RequireRole(ctx, auth.RoleAdmin); err != nil {
		return nil, err
	}
	// Get scan summaries from DB
	summaries, err := s.store.GetContainerSummaries(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get summaries: %w", err)
	}

	// Tag local summaries with backend_id
	scannedMap := make(map[string]bool)
	cleanCount := int32(0)
	infectedCount := int32(0)
	for _, sum := range summaries {
		sum.BackendId = s.localBackendID
		scannedMap[sum.ContainerName] = true
		if sum.LastStatus == "clean" {
			cleanCount++
		} else if sum.LastStatus == "infected" {
			infectedCount++
		}
	}

	// Get all running local containers to find never-scanned ones
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
					username := c.Name
					if strings.HasSuffix(c.Name, "-container") {
						username = strings.TrimSuffix(c.Name, "-container")
					}
					summaries = append(summaries, &pb.ClamavContainerSummary{
						ContainerName: c.Name,
						Username:      username,
						LastStatus:    "never",
						BackendId:     s.localBackendID,
					})
				}
			}
		}
	}

	// Fetch and merge peer security summaries (federated scanning)
	if s.peerPool != nil {
		authToken := extractAuthToken(ctx)
		peerSummaries, peerClean, peerInfected, peerNever := s.fetchPeerSummaries(authToken)
		summaries = append(summaries, peerSummaries...)
		cleanCount += peerClean
		infectedCount += peerInfected
		neverScanned += peerNever
	}

	return &pb.GetClamavSummaryResponse{
		Containers:             summaries,
		TotalContainers:        int32(len(summaries)), // #nosec G115 -- value bounded by container count
		CleanContainers:        cleanCount,
		InfectedContainers:     infectedCount,
		NeverScannedContainers: neverScanned,
		LastCollectionAt:       time.Now().Format(time.RFC3339),
	}, nil
}

// fetchPeerSummaries fetches ClamAV summaries from all peers in parallel.
// Returns merged summaries and aggregate counts.
func (s *SecurityServer) fetchPeerSummaries(authToken string) (summaries []*pb.ClamavContainerSummary, clean, infected, never int32) {
	peers := s.peerPool.Peers()
	if len(peers) == 0 {
		return
	}

	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, peer := range peers {
		if !peer.Healthy {
			continue
		}
		wg.Add(1)
		go func(pc *PeerClient) {
			defer wg.Done()
			body, err := pc.ForwardSecuritySummary(authToken)
			if err != nil {
				log.Printf("[security] failed to fetch summary from peer %s: %v", pc.ID, err)
				return
			}
			var resp pb.GetClamavSummaryResponse
			if err := protojson.Unmarshal(body, &resp); err != nil {
				log.Printf("[security] failed to parse summary from peer %s: %v", pc.ID, err)
				return
			}
			// Tag containers with peer's backend_id
			for _, c := range resp.Containers {
				if c.BackendId == "" {
					c.BackendId = pc.ID
				}
			}
			mu.Lock()
			summaries = append(summaries, resp.Containers...)
			clean += resp.CleanContainers
			infected += resp.InfectedContainers
			never += resp.NeverScannedContainers
			mu.Unlock()
		}(peer)
	}
	wg.Wait()
	return
}

// TriggerClamavScan enqueues scan jobs asynchronously and returns immediately.
// Phase 1.4 — when ContainerName is set, tenant authz via the
// owner derivation; when blank, the request enqueues scans for
// every container on every peer, so require admin.
func (s *SecurityServer) TriggerClamavScan(ctx context.Context, req *pb.TriggerClamavScanRequest) (*pb.TriggerClamavScanResponse, error) {
	if err := auth.RequireScope(ctx, auth.ScopeSecurityWrite); err != nil {
		return nil, err
	}
	if req.ContainerName == "" {
		if err := auth.RequireRole(ctx, auth.RoleAdmin); err != nil {
			return nil, err
		}
	} else {
		if err := auth.AuthorizeContainerAccess(ctx, req.ContainerName); err != nil {
			return nil, err
		}
	}
	if s.scanner == nil {
		return nil, fmt.Errorf("security scanner is not available")
	}

	authToken := extractAuthToken(ctx)

	if req.ContainerName != "" {
		// Check if this container is on a peer
		if s.peerPool != nil {
			username := req.ContainerName
			if strings.HasSuffix(username, "-container") {
				username = strings.TrimSuffix(username, "-container")
			}
			if peer := s.peerPool.FindContainerPeer(username, authToken); peer != nil {
				// Forward scan to the peer that owns this container
				_, err := peer.ForwardTriggerScan(authToken, req.ContainerName)
				if err != nil {
					return nil, fmt.Errorf("failed to trigger scan on peer %s: %w", peer.ID, err)
				}
				return &pb.TriggerClamavScanResponse{
					Message:      fmt.Sprintf("Scan queued for container %s on peer %s", req.ContainerName, peer.ID),
					ScannedCount: 1,
				}, nil
			}
		}

		// Local container scan
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

	// Enqueue scans for all running local user containers
	count, err := s.scanner.EnqueueAll(ctx)
	if err != nil {
		return nil, fmt.Errorf("enqueue all failed: %w", err)
	}

	// Also trigger scans on all peers
	peerCount := int32(0)
	if s.peerPool != nil {
		peerCount = s.triggerPeerScans(authToken)
	}

	totalCount := int32(count) + peerCount // #nosec G115 -- value bounded by container count
	return &pb.TriggerClamavScanResponse{
		Message:      fmt.Sprintf("%d scan jobs queued (%d local, %d on peers)", totalCount, count, peerCount),
		ScannedCount: totalCount,
	}, nil
}

// triggerPeerScans triggers scan-all on each healthy peer in parallel.
func (s *SecurityServer) triggerPeerScans(authToken string) int32 {
	peers := s.peerPool.Peers()
	if len(peers) == 0 {
		return 0
	}

	var mu sync.Mutex
	var wg sync.WaitGroup
	total := int32(0)

	for _, peer := range peers {
		if !peer.Healthy {
			continue
		}
		wg.Add(1)
		go func(pc *PeerClient) {
			defer wg.Done()
			body, err := pc.ForwardTriggerScan(authToken, "")
			if err != nil {
				log.Printf("[security] failed to trigger scan on peer %s: %v", pc.ID, err)
				return
			}
			var resp struct {
				ScannedCount int32 `json:"scannedCount"`
			}
			if err := json.Unmarshal(body, &resp); err == nil {
				mu.Lock()
				total += resp.ScannedCount
				mu.Unlock()
			}
		}(peer)
	}
	wg.Wait()
	return total
}

// GetScanStatus returns the current state of the scan job queue.
// Admin-only — the queue lists work items across all containers.
func (s *SecurityServer) GetScanStatus(ctx context.Context, req *pb.GetScanStatusRequest) (*pb.GetScanStatusResponse, error) {
	if err := auth.RequireScope(ctx, auth.ScopeSecurityRead); err != nil {
		return nil, err
	}
	if err := auth.RequireRole(ctx, auth.RoleAdmin); err != nil {
		return nil, err
	}
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
			RetryCount:    int32(j.RetryCount), // #nosec G115 -- retry count is a small integer
			ErrorMessage:  j.ErrorMessage,
			CreatedAt:     j.CreatedAt.Format(time.RFC3339),
			BackendId:     s.localBackendID,
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

	// Merge scan status from peers
	if s.peerPool != nil {
		authToken := extractAuthToken(ctx)
		s.mergePeerScanStatus(authToken, resp)
	}

	return resp, nil
}

// mergePeerScanStatus fetches scan job status from all peers and merges into resp.
func (s *SecurityServer) mergePeerScanStatus(authToken string, resp *pb.GetScanStatusResponse) {
	peers := s.peerPool.Peers()
	if len(peers) == 0 {
		return
	}

	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, peer := range peers {
		if !peer.Healthy {
			continue
		}
		wg.Add(1)
		go func(pc *PeerClient) {
			defer wg.Done()
			body, err := pc.ForwardScanStatus(authToken)
			if err != nil {
				log.Printf("[security] failed to fetch scan status from peer %s: %v", pc.ID, err)
				return
			}
			var peerResp pb.GetScanStatusResponse
			if err := protojson.Unmarshal(body, &peerResp); err != nil {
				log.Printf("[security] failed to parse scan status from peer %s: %v", pc.ID, err)
				return
			}
			// Tag peer jobs with backend_id
			for _, j := range peerResp.Jobs {
				if j.BackendId == "" {
					j.BackendId = pc.ID
				}
			}
			mu.Lock()
			resp.Jobs = append(resp.Jobs, peerResp.Jobs...)
			resp.PendingCount += peerResp.PendingCount
			resp.RunningCount += peerResp.RunningCount
			resp.CompletedCount += peerResp.CompletedCount
			resp.FailedCount += peerResp.FailedCount
			mu.Unlock()
		}(peer)
	}
	wg.Wait()
}
