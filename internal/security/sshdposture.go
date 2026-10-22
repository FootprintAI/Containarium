package security

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/footprintai/containarium/internal/threatdetect"
	"github.com/footprintai/containarium/pkg/core/incus"
	"github.com/footprintai/containarium/pkg/core/sshdpolicy"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// DefaultSSHDPostureInterval is how often every running box's sshd
// configuration is re-read and the managed drop-in re-asserted. Minutes,
// not the ClamAV scanner's day: a tenant edit must not stay live for long,
// and the pass is a handful of file reads per box through the incus file
// API — no rootfs mount, no exec inside the box.
const DefaultSSHDPostureInterval = 10 * time.Minute

// sshdReloadScript reloads whichever unit name the box's distro uses
// (Debian: ssh, RHEL: sshd). A box whose sshd is not running has nothing
// to reload and that is not an error here.
const sshdReloadScript = "systemctl reload sshd 2>/dev/null || systemctl reload ssh 2>/dev/null || true"

// SSHDPostureReconciler keeps every running box's sshd key-only (#2424).
//
// Anything written inside a box is advisory — the owner is root there and
// can delete the drop-in, add one that sorts earlier, or run a second sshd.
// The guarantee lives outside the box (the sentinel offers no password
// method and pipes to the key-only host sshd; the tenant guard limits who
// can reach a box's port 22). This reconciler is the layer that keeps the
// stock sshd honest and makes tampering VISIBLE: each pass re-reads the
// effective configuration through the incus file API, rewrites the managed
// drop-in if it is missing or altered, and records what it found as a
// security finding so a tenant edit lasts at most one interval and leaves
// an audit record.
//
// Backfill is silent: a box that has never been brought under policy
// (no marker in its incus config — host-side state the tenant cannot
// touch) gets the drop-in without a finding, because the image default is
// not the tenant's doing. From then on, a missing or altered drop-in is.
type SSHDPostureReconciler struct {
	incus    incus.Backend
	sink     threatdetect.FindingSink // nil = log only
	interval time.Duration
	now      func() time.Time

	mu        sync.Mutex
	backendID string
	cancel    context.CancelFunc

	// listenerCheck enables the rogue SSH listener probe (#2439), one exec
	// per running box per pass. On unless an operator turns it off.
	listenerCheck bool
}

// NewSSHDPostureReconciler builds a reconciler over backend. sink may be
// nil (findings are then only logged); interval <= 0 means
// DefaultSSHDPostureInterval.
func NewSSHDPostureReconciler(backend incus.Backend, sink threatdetect.FindingSink, interval time.Duration) *SSHDPostureReconciler {
	if interval <= 0 {
		interval = DefaultSSHDPostureInterval
	}
	return &SSHDPostureReconciler{incus: backend, sink: sink, interval: interval, now: time.Now, listenerCheck: true}
}

// SetListenerCheck turns the rogue SSH listener probe (#2439) on or off.
// It is on by default; it costs one exec per running box per pass.
func (r *SSHDPostureReconciler) SetListenerCheck(on bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.listenerCheck = on
}

func (r *SSHDPostureReconciler) listenerCheckEnabled() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.listenerCheck
}

// SetBackendID sets the backend id stamped onto findings. Deferred to the
// daemon's Start, like the threat engine's, because the local backend id
// is not known until the peer pool starts.
func (r *SSHDPostureReconciler) SetBackendID(id string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.backendID = id
}

func (r *SSHDPostureReconciler) getBackendID() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.backendID
}

// Start runs a pass shortly after startup, then every interval, until ctx
// is cancelled or Stop is called.
func (r *SSHDPostureReconciler) Start(ctx context.Context) {
	ctx, r.cancel = context.WithCancel(ctx)
	go func() {
		timer := time.NewTimer(2 * time.Minute)
		defer timer.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-timer.C:
				s := r.ReconcileAll(ctx)
				log.Printf("[sshd-posture] pass: %s", s)
				timer.Reset(r.interval)
			}
		}
	}()
	log.Printf("Box sshd posture reconciler started (interval: %v)", r.interval)
}

// Stop ends the background loop.
func (r *SSHDPostureReconciler) Stop() {
	if r.cancel != nil {
		r.cancel()
	}
}

// BoxOutcome is what one ReconcileBox pass concluded.
type BoxOutcome struct {
	// Skipped is non-empty when the box was not evaluated (no sshd_config).
	Skipped string
	// Backfilled: first time under policy; drop-in written, no finding.
	Backfilled bool
	// Remediated: the managed drop-in was rewritten this pass.
	Remediated bool
	// Compliant: the effective configuration refuses password login after
	// this pass.
	Compliant bool
	// Finding is non-nil when a finding was raised (or would have been,
	// with no sink configured).
	Finding *threatdetect.Finding
}

// Summary totals one ReconcileAll pass.
type Summary struct {
	Boxes, Skipped, Backfilled, Remediated, Findings, Listeners, Errors int
}

func (s Summary) String() string {
	return fmt.Sprintf("boxes=%d skipped=%d backfilled=%d remediated=%d findings=%d rogue_listeners=%d errors=%d",
		s.Boxes, s.Skipped, s.Backfilled, s.Remediated, s.Findings, s.Listeners, s.Errors)
}

// ReconcileAll runs ReconcileBox over every running, non-core container.
func (r *SSHDPostureReconciler) ReconcileAll(ctx context.Context) Summary {
	var s Summary
	containers, err := r.incus.ListContainers()
	if err != nil {
		log.Printf("[sshd-posture] list containers: %v", err)
		s.Errors++
		return s
	}
	for _, c := range containers {
		if ctx.Err() != nil {
			return s
		}
		if c.State != "Running" || c.Role.IsCoreRole() {
			continue
		}
		s.Boxes++
		if r.listenerCheckEnabled() {
			n, lerr := r.ReconcileListeners(ctx, c.Name)
			if lerr != nil {
				log.Printf("[sshd-posture] %s: listeners: %v", c.Name, lerr)
				s.Errors++
			}
			s.Listeners += n
		}
		out, err := r.ReconcileBox(ctx, c.Name)
		if err != nil {
			// The outcome is still tallied: a pass can remediate and raise
			// a finding and also fail to mark the box.
			log.Printf("[sshd-posture] %s: %v", c.Name, err)
			s.Errors++
		}
		switch {
		case out.Skipped != "":
			s.Skipped++
		case out.Backfilled:
			s.Backfilled++
		}
		if out.Remediated {
			s.Remediated++
		}
		if out.Finding != nil {
			s.Findings++
		}
	}
	return s
}

// ReconcileBox evaluates one box, re-asserts the managed drop-in when it is
// missing or altered, and raises a finding when the box had been under
// policy before (marker set) or is still permissive afterwards.
func (r *SSHDPostureReconciler) ReconcileBox(ctx context.Context, name string) (BoxOutcome, error) {
	main, err := r.incus.ReadFile(name, sshdpolicy.MainConfigPath)
	if err != nil {
		// No OpenSSH server in this box (minimal image, or sshd removed):
		// nothing listens for passwords, nothing to assert.
		return BoxOutcome{Skipped: "no " + sshdpolicy.MainConfigPath}, nil
	}
	dropIns := r.readDropIns(name)
	before := sshdpolicy.Evaluate(sshdpolicy.Merge(string(main), dropIns))
	intact := sshdpolicy.ManagedDropInIntact(dropIns)

	cfg, _, cfgErr := r.incus.GetRawInstance(name)
	if cfgErr != nil {
		return BoxOutcome{}, fmt.Errorf("read instance config: %w", cfgErr)
	}
	marked := cfg[sshdpolicy.MarkerKey] == sshdpolicy.MarkerValue

	if intact && before.Compliant() {
		if !marked {
			if err := r.mark(name); err != nil {
				return BoxOutcome{Compliant: true}, err
			}
		}
		return BoxOutcome{Compliant: true}, nil
	}

	out := BoxOutcome{}
	observed := dropIns // as found, before any re-assert — what the evidence describes
	if !intact {
		if err := r.writeDropIn(name); err != nil {
			return out, fmt.Errorf("re-assert drop-in: %w", err)
		}
		out.Remediated = true
		dropIns = withManagedDropIn(dropIns)
	}
	after := sshdpolicy.Evaluate(sshdpolicy.Merge(string(main), dropIns))
	out.Compliant = after.Compliant()

	var markErr error
	if !marked {
		markErr = r.mark(name)
		if markErr == nil && out.Compliant {
			// First time under policy: the image default, not the tenant.
			out.Backfilled = true
			return out, nil
		}
		// A failed mark cannot vouch for the box: without the marker the
		// next pass would backfill it silently again, so what this pass
		// found is reported as a finding rather than assumed to be the
		// image default. The error is returned so the pass counts it.
	}

	f := r.buildFinding(name, string(main), observed, before, intact, out.Remediated, out.Compliant)
	out.Finding = f
	if r.sink == nil {
		log.Printf("[sshd-posture] %s: %s (no finding sink configured)", name, describe(f))
		return out, markErr
	}
	if _, err := r.sink.Upsert(ctx, f); err != nil {
		return out, errors.Join(fmt.Errorf("record finding: %w", err), markErr)
	}
	log.Printf("[sshd-posture] %s: finding recorded: %s", name, describe(f))
	return out, markErr
}

// readDropIns returns every *.conf under DropInDir that could be read. A
// missing directory is an empty set — the write path creates it.
func (r *SSHDPostureReconciler) readDropIns(name string) []sshdpolicy.DropIn {
	entries, err := r.incus.ListDir(name, sshdpolicy.DropInDir)
	if err != nil {
		return nil
	}
	var out []sshdpolicy.DropIn
	for _, e := range entries {
		if !strings.HasSuffix(e, ".conf") || strings.Contains(e, "/") {
			continue
		}
		content, rerr := r.incus.ReadFile(name, sshdpolicy.DropInDir+"/"+e)
		if rerr != nil {
			continue
		}
		out = append(out, sshdpolicy.DropIn{Name: e, Content: string(content)})
	}
	return out
}

func (r *SSHDPostureReconciler) writeDropIn(name string) error {
	if err := r.incus.Exec(name, []string{"mkdir", "-p", sshdpolicy.DropInDir}); err != nil {
		return fmt.Errorf("mkdir %s: %w", sshdpolicy.DropInDir, err)
	}
	if err := r.incus.WriteFile(name, sshdpolicy.DropInPath, sshdpolicy.DropInContent(), sshdpolicy.DropInMode); err != nil {
		return err
	}
	if err := r.incus.Exec(name, []string{"sh", "-c", sshdReloadScript}); err != nil {
		// The file is in place; the next sshd (re)start picks it up. Log,
		// don't fail: the write is the durable part.
		log.Printf("[sshd-posture] %s: sshd reload: %v", name, err)
	}
	return nil
}

// mark stamps the host-side marker. The error is returned, not just logged:
// an unmarked box reads as "never under policy" on the next pass, which is
// the silent-backfill exemption.
func (r *SSHDPostureReconciler) mark(name string) error {
	if err := r.incus.SetConfig(name, sshdpolicy.MarkerKey, sshdpolicy.MarkerValue); err != nil {
		return fmt.Errorf("set %s: %w", sshdpolicy.MarkerKey, err)
	}
	return nil
}

// withManagedDropIn returns dropIns with the managed file replaced by (or
// added as) its canonical content — what the box has after writeDropIn.
func withManagedDropIn(dropIns []sshdpolicy.DropIn) []sshdpolicy.DropIn {
	out := make([]sshdpolicy.DropIn, 0, len(dropIns)+1)
	for _, d := range dropIns {
		if d.Name != sshdpolicy.DropInName {
			out = append(out, d)
		}
	}
	return append(out, sshdpolicy.DropIn{Name: sshdpolicy.DropInName, Content: string(sshdpolicy.DropInContent())})
}

// buildFinding turns one pass's observations into the finding to record.
// Severity is HIGH while the box still permits passwords after the
// re-assert (something of the tenant's outranks the managed drop-in) and
// MEDIUM when the pass closed it (tampering that is now undone).
func (r *SSHDPostureReconciler) buildFinding(name, main string, dropIns []sshdpolicy.DropIn,
	before sshdpolicy.Result, intact, remediated, compliantNow bool) *threatdetect.Finding {
	var ev []threatdetect.ConfigEvidence
	for _, v := range before.Violations {
		ev = append(ev, threatdetect.ConfigEvidence{
			Path:       attribute(main, dropIns, v.Directive),
			Directive:  v.Directive,
			Value:      v.Value,
			Remediated: remediated && compliantNow,
		})
	}
	if !intact {
		note := "managed drop-in missing"
		for _, d := range dropIns {
			if d.Name == sshdpolicy.DropInName && d.Content != string(sshdpolicy.DropInContent()) {
				note = "managed drop-in altered"
			}
		}
		ev = append(ev, threatdetect.ConfigEvidence{
			Path:       sshdpolicy.DropInPath,
			Directive:  "ManagedDropIn",
			Value:      "absent",
			Remediated: remediated,
			Note:       note,
		})
	}
	sev := pb.ThreatSeverity_THREAT_SEVERITY_MEDIUM
	if !compliantNow {
		sev = pb.ThreatSeverity_THREAT_SEVERITY_HIGH
	}
	username := strings.TrimSuffix(name, "-container")
	return &threatdetect.Finding{
		Rule:      pb.ThreatRuleId_THREAT_RULE_ID_BOX_SSHD_PASSWORD_AUTH,
		Severity:  sev,
		TenantID:  username,
		Container: name,
		BackendID: r.getBackendID(),
		Subject:   name,
		Evidence:  threatdetect.Evidence{Configs: ev},
		FirstSeen: r.now(),
	}
}

// attribute names the file whose directive sshd honours: the lexically
// first drop-in that sets it, else the main file. Mirrors Merge's order so
// the evidence points at the line an operator has to look at.
func attribute(main string, dropIns []sshdpolicy.DropIn, directive string) string {
	sorted := append([]sshdpolicy.DropIn(nil), dropIns...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })
	for _, d := range sorted {
		if !strings.HasSuffix(d.Name, ".conf") {
			continue
		}
		if sshdpolicy.Directive(d.Content, directive, "") != "" {
			return sshdpolicy.DropInDir + "/" + d.Name
		}
	}
	if sshdpolicy.Directive(main, directive, "") != "" {
		return sshdpolicy.MainConfigPath
	}
	return sshdpolicy.MainConfigPath + " (sshd default)"
}

func describe(f *threatdetect.Finding) string {
	parts := make([]string, 0, len(f.Evidence.Configs))
	for _, c := range f.Evidence.Configs {
		s := c.Directive + "=" + c.Value + " (" + c.Path
		if c.Remediated {
			s += ", remediated"
		}
		parts = append(parts, s+")")
	}
	return strings.TrimPrefix(f.Severity.String(), "THREAT_SEVERITY_") + ": " + strings.Join(parts, "; ")
}
