package sentinel

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	compute "cloud.google.com/go/compute/apiv1"
	computepb "cloud.google.com/go/compute/apiv1/computepb"
	"google.golang.org/api/iterator"
)

// GCPProvider implements CloudProvider and EventWatcher using the GCP Compute Engine API.
type GCPProvider struct {
	client    *compute.InstancesClient
	opsClient *compute.ZoneOperationsClient
	project   string
	zone      string
	instance  string
}

// NewGCPProvider creates a GCP cloud provider.
// Auth is handled via the metadata server (on GCE) or GOOGLE_APPLICATION_CREDENTIALS.
func NewGCPProvider(ctx context.Context, project, zone, instanceName string) (*GCPProvider, error) {
	client, err := compute.NewInstancesRESTClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCP compute client: %w", err)
	}
	opsClient, err := compute.NewZoneOperationsRESTClient(ctx)
	if err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("failed to create GCP operations client: %w", err)
	}
	return &GCPProvider{
		client:    client,
		opsClient: opsClient,
		project:   project,
		zone:      zone,
		instance:  instanceName,
	}, nil
}

func (g *GCPProvider) GetInstanceStatus(ctx context.Context) (InstanceStatus, error) {
	inst, err := g.client.Get(ctx, &computepb.GetInstanceRequest{
		Project:  g.project,
		Zone:     g.zone,
		Instance: g.instance,
	})
	if err != nil {
		return StatusUnknown, fmt.Errorf("failed to get instance: %w", err)
	}

	if inst.Status == nil {
		return StatusUnknown, nil
	}
	return mapGCPStatus(*inst.Status), nil
}

func (g *GCPProvider) GetInstanceIP(ctx context.Context) (string, error) {
	inst, err := g.client.Get(ctx, &computepb.GetInstanceRequest{
		Project:  g.project,
		Zone:     g.zone,
		Instance: g.instance,
	})
	if err != nil {
		return "", fmt.Errorf("failed to get instance: %w", err)
	}

	for _, iface := range inst.NetworkInterfaces {
		if iface.NetworkIP != nil {
			return *iface.NetworkIP, nil
		}
	}
	return "", fmt.Errorf("no internal IP found for instance %s", g.instance)
}

func (g *GCPProvider) StartInstance(ctx context.Context) error {
	_, err := g.client.Start(ctx, &computepb.StartInstanceRequest{
		Project:  g.project,
		Zone:     g.zone,
		Instance: g.instance,
	})
	if err != nil {
		return fmt.Errorf("failed to start instance: %w", err)
	}
	return nil
}

// WatchEvents polls GCP zone operations for VM lifecycle events (preemption, stop, start).
// Sends events to the channel. Blocks until ctx is cancelled.
func (g *GCPProvider) WatchEvents(ctx context.Context, events chan<- VMEvent) error {
	// Track the latest operation we've seen to avoid duplicates
	var lastSeenTime time.Time
	pollInterval := 10 * time.Second

	// On first run, only look at operations from the last 5 minutes
	lastSeenTime = time.Now().Add(-5 * time.Minute)

	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			g.pollOperations(ctx, events, &lastSeenTime)
		}
	}
}

func (g *GCPProvider) pollOperations(ctx context.Context, events chan<- VMEvent, lastSeenTime *time.Time) {
	// Filter for operations targeting our instance
	filter := fmt.Sprintf("targetLink=\"*/instances/%s\" AND (operationType=\"compute.instances.stop\" OR operationType=\"compute.instances.start\" OR operationType=\"compute.instances.delete\")", g.instance)

	it := g.opsClient.List(ctx, &computepb.ListZoneOperationsRequest{
		Project:    g.project,
		Zone:       g.zone,
		Filter:     &filter,
		MaxResults: ptr(uint32(20)),
	})

	for {
		op, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			log.Printf("[sentinel] watcher: failed to list operations: %v", err)
			break
		}

		if op.InsertTime == nil {
			continue
		}

		// Parse the operation timestamp
		opTime, err := time.Parse(time.RFC3339, *op.InsertTime)
		if err != nil {
			continue
		}

		// Skip operations we've already seen
		if !opTime.After(*lastSeenTime) {
			continue
		}
		*lastSeenTime = opTime

		event := g.operationToEvent(op, opTime)
		if event != nil {
			select {
			case events <- *event:
			case <-ctx.Done():
				return
			}
		}
	}
}

func (g *GCPProvider) operationToEvent(op *computepb.Operation, opTime time.Time) *VMEvent {
	if op.OperationType == nil {
		return nil
	}

	opType := *op.OperationType
	statusMsg := ""
	if op.StatusMessage != nil {
		statusMsg = *op.StatusMessage
	}

	// Detect preemption: GCP sets statusMessage containing "preempted" on spot VM stops
	isPreemption := strings.Contains(strings.ToLower(statusMsg), "preempt")

	switch {
	case strings.Contains(opType, "stop") && isPreemption:
		return &VMEvent{
			Type:      EventPreempted,
			Timestamp: opTime,
			Detail:    fmt.Sprintf("spot VM preempted: %s", statusMsg),
		}
	case strings.Contains(opType, "stop"):
		return &VMEvent{
			Type:      EventStopped,
			Timestamp: opTime,
			Detail:    fmt.Sprintf("VM stopped: %s", statusMsg),
		}
	case strings.Contains(opType, "start"):
		return &VMEvent{
			Type:      EventStarted,
			Timestamp: opTime,
			Detail:    fmt.Sprintf("VM started: %s", statusMsg),
		}
	case strings.Contains(opType, "delete"):
		return &VMEvent{
			Type:      EventTerminated,
			Timestamp: opTime,
			Detail:    fmt.Sprintf("VM deleted: %s", statusMsg),
		}
	}

	return nil
}

// Close releases the GCP client resources.
func (g *GCPProvider) Close() error {
	_ = g.opsClient.Close()
	return g.client.Close()
}

func ptr[T any](v T) *T {
	return &v
}

func mapGCPStatus(status string) InstanceStatus {
	switch strings.ToUpper(status) {
	case "RUNNING":
		return StatusRunning
	case "STOPPED", "SUSPENDED":
		return StatusStopped
	case "TERMINATED":
		return StatusTerminated
	case "PROVISIONING", "STAGING":
		return StatusProvisioning
	default:
		return StatusUnknown
	}
}
