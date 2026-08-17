package server

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	clusterstore "github.com/footprintai/containarium/internal/cluster"
)

// clusterCaps is the operator's hard ceiling on what any tenant may
// configure a managed cluster to consume (#1417, PRD story 5). Zero
// values mean unlimited. Enforced server-side at create and node-pool
// update; a refused request is a typed error (and a REFUSED scale
// event on updates) — never a silent clamp.
type clusterCaps struct {
	// configErr poisons the caps: every check fails with it. Set when
	// the operator's cap configuration cannot be parsed — a typo must
	// fail closed, not silently leave the gate open.
	configErr error
	// maxNodes bounds the SUM of max_nodes across a cluster's groups
	// — the worst-case VM count a tenant's autoscaler may reach.
	maxNodes int32
	// Per-node size ceilings.
	maxCPU         int
	maxMemoryBytes int64
	maxDiskBytes   int64
}

// SetCaps installs the caps (SetCapsFromEnv in production; direct in
// tests).
func (s *ClusterServer) SetCaps(c clusterCaps) { s.caps = c }

// SetCapsFromEnv parses CONTAINARIUM_CLUSTER_MAX_NODES and
// CONTAINARIUM_CLUSTER_MAX_NODE_SIZE ("cpu=8,memory=16GB,disk=200GB").
// A malformed value is a startup error — a typo must not silently
// leave the gate open.
func (s *ClusterServer) SetCapsFromEnv(maxNodes, maxNodeSize string) error {
	caps, err := parseClusterCaps(maxNodes, maxNodeSize)
	if err != nil {
		return err
	}
	s.caps = caps
	return nil
}

var sizeBytesRE = regexp.MustCompile(`^([1-9][0-9]*)(MB|GB|TB)$`)

// sizeToBytes parses the house size format ("16GB") into bytes
// (decimal units, matching the format ValidateNodeGroups accepts).
func sizeToBytes(s string) (int64, error) {
	m := sizeBytesRE.FindStringSubmatch(s)
	if m == nil {
		return 0, fmt.Errorf("invalid size %q (want e.g. 16GB)", s)
	}
	n, err := strconv.ParseInt(m[1], 10, 64)
	if err != nil {
		return 0, err
	}
	switch m[2] {
	case "MB":
		return n * 1_000_000, nil
	case "GB":
		return n * 1_000_000_000, nil
	default: // TB
		return n * 1_000_000_000_000, nil
	}
}

func parseClusterCaps(maxNodes, maxNodeSize string) (clusterCaps, error) {
	var caps clusterCaps
	if maxNodes != "" {
		n, err := strconv.ParseInt(maxNodes, 10, 32)
		if err != nil || n < 1 {
			return caps, fmt.Errorf("CONTAINARIUM_CLUSTER_MAX_NODES %q: want a positive integer", maxNodes)
		}
		caps.maxNodes = int32(n)
	}
	if maxNodeSize == "" {
		return caps, nil
	}
	for _, kv := range strings.Split(maxNodeSize, ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(kv), "=")
		if !ok {
			return caps, fmt.Errorf("CONTAINARIUM_CLUSTER_MAX_NODE_SIZE: %q is not key=value", kv)
		}
		switch k {
		case "cpu":
			n, err := strconv.Atoi(v)
			if err != nil || n < 1 {
				return caps, fmt.Errorf("CONTAINARIUM_CLUSTER_MAX_NODE_SIZE cpu %q: want a positive integer", v)
			}
			caps.maxCPU = n
		case "memory":
			b, err := sizeToBytes(v)
			if err != nil {
				return caps, fmt.Errorf("CONTAINARIUM_CLUSTER_MAX_NODE_SIZE memory: %w", err)
			}
			caps.maxMemoryBytes = b
		case "disk":
			b, err := sizeToBytes(v)
			if err != nil {
				return caps, fmt.Errorf("CONTAINARIUM_CLUSTER_MAX_NODE_SIZE disk: %w", err)
			}
			caps.maxDiskBytes = b
		default:
			return caps, fmt.Errorf("CONTAINARIUM_CLUSTER_MAX_NODE_SIZE: unknown key %q (want cpu/memory/disk)", k)
		}
	}
	return caps, nil
}

// check validates a replacement group set against the caps. Groups are
// assumed already structurally valid (ValidateNodeGroups).
func (c clusterCaps) check(groups []clusterstore.NodeGroup) error {
	if c.configErr != nil {
		return fmt.Errorf("cluster caps misconfigured (%v); refusing until fixed", c.configErr)
	}
	if c.maxNodes > 0 {
		var total int32
		for _, g := range groups {
			total += g.MaxNodes
		}
		if total > c.maxNodes {
			return fmt.Errorf("total max_nodes %d exceeds the platform cap of %d", total, c.maxNodes)
		}
	}
	for _, g := range groups {
		if c.maxCPU > 0 {
			if cpu, _ := strconv.Atoi(g.Size.CPU); cpu > c.maxCPU {
				return fmt.Errorf("node group %q: cpu %s exceeds the platform cap of %d", g.Name, g.Size.CPU, c.maxCPU)
			}
		}
		if c.maxMemoryBytes > 0 {
			if b, err := sizeToBytes(g.Size.Memory); err == nil && b > c.maxMemoryBytes {
				return fmt.Errorf("node group %q: memory %s exceeds the platform cap", g.Name, g.Size.Memory)
			}
		}
		if c.maxDiskBytes > 0 {
			if b, err := sizeToBytes(g.Size.Disk); err == nil && b > c.maxDiskBytes {
				return fmt.Errorf("node group %q: disk %s exceeds the platform cap", g.Name, g.Size.Disk)
			}
		}
	}
	return nil
}

// enforceCaps turns a cap violation into the typed refusal; when a
// cluster record exists (updates), the refusal also lands on its scale
// history so `cluster status` shows WHY the pool stopped growing.
func (s *ClusterServer) enforceCaps(ctx context.Context, owner, name string, groups []clusterstore.NodeGroup, recordEvent bool) error {
	err := s.caps.check(groups)
	if err == nil {
		return nil
	}
	if recordEvent {
		_ = s.store.AppendEvent(ctx, owner, name, clusterstore.Event{
			At: time.Now().UTC(), Kind: clusterstore.EventRefused,
			Reason: err.Error(),
		})
	}
	return status.Errorf(codes.InvalidArgument, "%v", err)
}
