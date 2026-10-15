package sshcontrol

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/footprintai/containarium/internal/sentinel/sshgate"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// policyHash binds restored history to the exact operator policy and inventory.
func (c *Controller) policyHash() string {
	data, _ := proto.MarshalOptions{Deterministic: true}.Marshal(c.cfg.Policy)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// privateDirectory refuses symlinks and accessible final state/socket directories.
func privateDirectory(path string) error {
	if !filepath.IsAbs(path) {
		return errors.New("private upstream path must be absolute")
	}
	if err := os.MkdirAll(path, 0700); err != nil {
		return err
	}
	for dir := path; dir != "/"; dir = filepath.Dir(dir) {
		st, err := os.Lstat(dir)
		if err != nil {
			return err
		}
		if !st.IsDir() || st.Mode()&os.ModeSymlink != 0 || (dir == path && st.Mode().Perm()&0077 != 0) {
			return fmt.Errorf("unsafe private upstream directory: %s", dir)
		}
	}
	return nil
}

// restore rejects incompatible/corrupt history instead of granting fresh budget.
func (c *Controller) restore() error {
	if err := privateDirectory(filepath.Dir(c.cfg.StatePath)); err != nil {
		return err
	}
	st, err := os.Lstat(c.cfg.StatePath)
	if errors.Is(err, os.ErrNotExist) {
		c.readyAt = c.cfg.Now().Add(c.cfg.Policy.Window.AsDuration())
		return c.persist()
	}
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 || st.Size() > 16<<20 {
		return errors.New("unsafe upstream checkpoint")
	}
	data, err := os.ReadFile(c.cfg.StatePath)
	if err != nil {
		return err
	}
	snapshot := &pb.SSHUpstreamCheckpoint{}
	if err := protojson.Unmarshal(data, snapshot); err != nil {
		return fmt.Errorf("invalid upstream checkpoint: %w", err)
	}
	if snapshot.PolicyHash != c.policyHash() || snapshot.ReadyAt == nil || snapshot.ReadyAt.CheckValid() != nil {
		return errors.New("incompatible upstream checkpoint policy or warmup")
	}
	if len(snapshot.Aliases) > int(c.cfg.Policy.MaxBackends)*16 {
		return errors.New("upstream checkpoint alias capacity")
	}
	rows := make([]sshgate.State, 0, len(snapshot.Backends))
	for _, b := range snapshot.Backends {
		if b.Delay == nil || b.Delay.CheckValid() != nil {
			return errors.New("invalid checkpoint delay")
		}
		s := sshgate.State{Key: sshgate.Key{Backend: b.BackendId, Egress: c.cfg.Policy.EgressGroup}, Route: b.RouteGeneration, Delay: b.Delay.AsDuration(), Blocked: b.Blocked}
		if b.NextProbeAt != nil {
			if b.NextProbeAt.CheckValid() != nil {
				return errors.New("invalid checkpoint deadline")
			}
			s.Next = b.NextProbeAt.AsTime()
		}
		for _, r := range b.Risks {
			if r.At == nil || r.At.CheckValid() != nil {
				return errors.New("invalid checkpoint risk time")
			}
			s.Risks = append(s.Risks, sshgate.Risk{At: r.At.AsTime(), Cost: int(r.Cost)})
		}
		rows = append(rows, s)
		c.versions[b.BackendId] = b.RouteGeneration
	}
	if err := c.gate.Restore(rows); err != nil {
		return err
	}
	for _, a := range snapshot.Aliases {
		if a.Alias == "" || c.versions[a.BackendId] == 0 || c.aliases[a.Alias] != "" {
			return errors.New("invalid checkpoint identity alias")
		}
		c.aliases[a.Alias] = a.BackendId
	}
	c.readyAt = snapshot.ReadyAt.AsTime()
	return nil
}

// persist poisons admission on failure and atomically syncs before acknowledging.
func (c *Controller) persist() (err error) {
	defer func() {
		if err != nil {
			c.fault = err
		}
	}()
	snapshot := &pb.SSHUpstreamCheckpoint{PolicyHash: c.policyHash(), ReadyAt: timestamppb.New(c.readyAt)}
	for _, s := range c.gate.Checkpoint() {
		b := &pb.SSHUpstreamBackendState{BackendId: s.Key.Backend, RouteGeneration: s.Route, Delay: durationpb.New(s.Delay), Blocked: s.Blocked}
		if !s.Next.IsZero() {
			b.NextProbeAt = timestamppb.New(s.Next)
		}
		for _, r := range s.Risks {
			if r.Cost < 1 || r.Cost > 65536 {
				return errors.New("checkpoint risk outside validated policy bounds")
			}
			b.Risks = append(b.Risks, &pb.SSHUpstreamRisk{At: timestamppb.New(r.At), Cost: uint32(r.Cost)})
		}
		snapshot.Backends = append(snapshot.Backends, b)
	}
	keys := make([]string, 0, len(c.aliases))
	for alias := range c.aliases {
		keys = append(keys, alias)
	}
	sort.Strings(keys)
	for _, alias := range keys {
		snapshot.Aliases = append(snapshot.Aliases, &pb.SSHUpstreamIdentityAlias{Alias: alias, BackendId: c.aliases[alias]})
	}
	data, err := protojson.Marshal(snapshot)
	if err != nil {
		return err
	}
	dir := filepath.Dir(c.cfg.StatePath)
	f, err := os.CreateTemp(dir, ".risk-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(f.Name()) }()
	if _, err = f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Rename(f.Name(), c.cfg.StatePath); err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer func() { _ = d.Close() }()
	return d.Sync()
}
