// Package depsguard is the Go half of the dependency-change gate (#2794,
// story 3 of #2649). It compares a PR's go.mod with its base and fails on:
//
//   - a new or changed `replace` directive (an existing, unchanged one passes,
//     so a deliberate pin that predates the PR is not re-litigated on every PR);
//   - a new or version-changed module that sum.golang.org has no record of, or
//     whose go.sum hash differs from the checksum database's;
//   - (CheckEnv) a Go environment that would bypass the checksum database.
//
// The go command consults the checksum database only for modules missing
// from go.sum, so a PR that adds a module *and* its go.sum lines is never
// checked by `go mod download` or `go mod verify`. That is the gap this
// closes: every new or changed requirement is looked up explicitly.
//
// It also lists each new module with its publication age (from the module
// proxy's .info timestamp) and source, for a reviewer to read. The policy is a
// hard fail with no label; the only override is a code-owner approval of the
// PR (decision 4 on #2649).
//
// Standard library only, by design: the gate must not widen the dependency
// graph it guards.
package depsguard

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"
)

// Default endpoints. The checksum database is named explicitly rather than
// taken from GOSUMDB so a misconfigured environment cannot point the gate at
// a database it controls; CheckEnv fails that environment separately.
const (
	DefaultSumDB = "https://sum.golang.org"
	DefaultProxy = "https://proxy.golang.org"
	// SumDBName is the only GOSUMDB value CheckEnv accepts.
	SumDBName = "sum.golang.org"
	// YoungAge: modules published more recently than this are bold in the
	// report (#2649 story 3).
	YoungAge = 14 * 24 * time.Hour
	// Marker identifies the sticky PR comment so it is updated, not re-posted.
	Marker = "<!-- deps-guard -->"
)

// ModuleVersion is a module path with an optional version, as in
// `go mod edit -json`. A replacement with an empty Version is a local path.
type ModuleVersion struct {
	Path    string `json:"Path"`
	Version string `json:"Version,omitempty"`
}

// Require is one `require` line.
type Require struct {
	Path     string `json:"Path"`
	Version  string `json:"Version"`
	Indirect bool   `json:"Indirect,omitempty"`
}

// Replace is one `replace` directive.
type Replace struct {
	Old ModuleVersion `json:"Old"`
	New ModuleVersion `json:"New"`
}

func (r Replace) String() string {
	s := r.Old.Path
	if r.Old.Version != "" {
		s += " " + r.Old.Version
	}
	s += " => " + r.New.Path
	if r.New.Version != "" {
		s += " " + r.New.Version
	}
	return s
}

// GoMod is the subset of `go mod edit -json` output the guard reads.
type GoMod struct {
	Require []Require `json:"Require"`
	Replace []Replace `json:"Replace"`
}

// ParseGoModJSON decodes `go mod edit -json` output.
func ParseGoModJSON(b []byte) (GoMod, error) {
	var m GoMod
	if err := json.Unmarshal(b, &m); err != nil {
		return GoMod{}, fmt.Errorf("decode go mod edit -json: %w", err)
	}
	return m, nil
}

// LoadGoMod parses a go.mod file with the go command's own parser. A missing
// file is an empty module (the base of a PR that adds go.mod).
func LoadGoMod(ctx context.Context, path string) (GoMod, error) {
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		return GoMod{}, nil
	}
	var stderr bytes.Buffer
	// #nosec G204 -- fixed binary and subcommand, no shell; path is a go.mod file
	// the CI script names, passed as one argument.
	cmd := exec.CommandContext(ctx, "go", "mod", "edit", "-json", path)
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return GoMod{}, fmt.Errorf("go mod edit -json %s: %w: %s", path, err, strings.TrimSpace(stderr.String()))
	}
	return ParseGoModJSON(out)
}

// GoSum maps "path version" and "path version/go.mod" to their h1: hash.
type GoSum map[string]string

// ParseGoSum parses a go.sum file.
func ParseGoSum(b []byte) (GoSum, error) {
	sum := GoSum{}
	for i, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		if len(f) != 3 {
			return nil, fmt.Errorf("go.sum line %d: want 3 fields, got %d", i+1, len(f))
		}
		sum[f[0]+" "+f[1]] = f[2]
	}
	return sum, nil
}

// FindingKind names the rule a finding broke. The CLI prints it, and the
// self-test matches each failing fixture on it, so a fixture that fails for
// the wrong reason does not count.
type FindingKind string

const (
	FindingReplaceAdded   FindingKind = "replace-added"
	FindingReplaceChanged FindingKind = "replace-changed"
	FindingNotInSumDB     FindingKind = "not-in-sumdb"
	FindingSumMismatch    FindingKind = "sum-mismatch"
	FindingUnsafeEnv      FindingKind = "unsafe-env"
)

// Finding is one policy failure.
type Finding struct {
	Kind   FindingKind
	Module string
	Detail string
}

func (f Finding) String() string { return fmt.Sprintf("%s %s: %s", f.Kind, f.Module, f.Detail) }

// GoEnv is the subset of `go env -json` that decides whether the checksum
// database is in force. Field names match the variables so the JSON decodes
// straight in.
type GoEnv struct {
	GOFLAGS    string
	GOSUMDB    string
	GONOSUMDB  string
	GOPRIVATE  string
	GONOPROXY  string
	GOINSECURE string
}

// GoEnvVars lists the variables to request from `go env -json`.
var GoEnvVars = []string{"GOFLAGS", "GOSUMDB", "GONOSUMDB", "GOPRIVATE", "GONOPROXY", "GOINSECURE"}

// CheckEnv fails an environment that lets a module skip the checksum
// database or lets a build rewrite go.mod. GOPRIVATE and GONOPROXY count
// because the go command derives GONOSUMDB from GOPRIVATE, and both mark
// modules as private, which this public repo has none of.
func CheckEnv(env GoEnv) []Finding {
	var out []Finding
	bad := func(name, detail string) {
		out = append(out, Finding{Kind: FindingUnsafeEnv, Module: name, Detail: detail})
	}
	readonly := false
	for _, f := range strings.Fields(env.GOFLAGS) {
		if f == "-mod=readonly" {
			readonly = true
		}
	}
	if !readonly {
		bad("GOFLAGS", fmt.Sprintf("%q does not contain -mod=readonly", env.GOFLAGS))
	}
	if env.GOSUMDB != SumDBName {
		bad("GOSUMDB", fmt.Sprintf("%q, want %q", env.GOSUMDB, SumDBName))
	}
	for name, v := range map[string]string{
		"GONOSUMDB": env.GONOSUMDB, "GOPRIVATE": env.GOPRIVATE,
		"GONOPROXY": env.GONOPROXY, "GOINSECURE": env.GOINSECURE,
	} {
		if v != "" {
			bad(name, fmt.Sprintf("set to %q; it exempts modules from the checksum database or TLS", v))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Module < out[j].Module })
	return out
}

// CheckReplaces fails every replace directive in head that is not present,
// identically, in base. A directive is identified by its left-hand side
// (path and optional version); a changed right-hand side is "changed", a new
// left-hand side is "added". Removing a replace passes.
func CheckReplaces(base, head GoMod) []Finding {
	baseBy := map[ModuleVersion]ModuleVersion{}
	for _, r := range base.Replace {
		baseBy[r.Old] = r.New
	}
	var out []Finding
	for _, r := range head.Replace {
		prev, ok := baseBy[r.Old]
		switch {
		case !ok:
			out = append(out, Finding{Kind: FindingReplaceAdded, Module: r.Old.Path,
				Detail: "new replace directive: " + r.String()})
		case prev != r.New:
			was := Replace{Old: r.Old, New: prev}
			out = append(out, Finding{Kind: FindingReplaceChanged, Module: r.Old.Path,
				Detail: "replace directive changed from `" + was.String() + "` to `" + r.String() + "`"})
		}
	}
	return out
}

// ModuleChange is a requirement that is new in head, or whose version moved.
type ModuleChange struct {
	Path       string
	OldVersion string // empty: the module is new
	NewVersion string
	Indirect   bool
}

// Added reports whether the module is new rather than re-versioned.
func (c ModuleChange) Added() bool { return c.OldVersion == "" }

// DiffRequires lists added and re-versioned requirements, sorted by path.
func DiffRequires(base, head GoMod) []ModuleChange {
	was := map[string]string{}
	for _, r := range base.Require {
		was[r.Path] = r.Version
	}
	var out []ModuleChange
	for _, r := range head.Require {
		old, ok := was[r.Path]
		if ok && old == r.Version {
			continue
		}
		out = append(out, ModuleChange{Path: r.Path, OldVersion: old, NewVersion: r.Version, Indirect: r.Indirect})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

// EscapePath applies the module proxy / checksum database case encoding:
// every upper-case letter becomes '!' plus its lower-case form. It is used
// for both paths and versions, which share the rule.
func EscapePath(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= 'A' && r <= 'Z' {
			b.WriteByte('!')
			r += 'a' - 'A'
		}
		b.WriteRune(r)
	}
	return b.String()
}

// SumRecord is the checksum database's record for one module version.
type SumRecord struct {
	Hash      string // h1: of the module zip
	GoModHash string // h1: of its go.mod
}

// SumDB looks a module version up in the checksum database. found=false with
// a nil error means the database has no record; any other trouble is an
// error, never "not found" or "found".
type SumDB interface {
	Lookup(ctx context.Context, path, version string) (rec SumRecord, found bool, err error)
}

// Origin is the VCS origin the module proxy records for a version.
type Origin struct {
	VCS string `json:"VCS"`
	URL string `json:"URL"`
}

// ModuleInfo is the proxy's .info document.
type ModuleInfo struct {
	Version string    `json:"Version"`
	Time    time.Time `json:"Time"`
	Origin  *Origin   `json:"Origin,omitempty"`
}

// Proxy fetches a module version's .info document.
type Proxy interface {
	Info(ctx context.Context, path, version string) (ModuleInfo, error)
}

const maxBody = 1 << 20

// HTTPSumDB queries a checksum database's /lookup endpoint. It does not
// verify the signed tree note: TLS to the named database is the trust anchor
// here, and the go command verifies the tree itself on every download.
type HTTPSumDB struct {
	BaseURL  string
	Client   *http.Client
	Attempts int // default 3; retried on transport errors and 5xx only
}

func (s HTTPSumDB) Lookup(ctx context.Context, path, version string) (SumRecord, bool, error) {
	url := strings.TrimRight(s.BaseURL, "/") + "/lookup/" + EscapePath(path) + "@" + EscapePath(version)
	status, body, err := get(ctx, s.Client, url, s.Attempts)
	if err != nil {
		return SumRecord{}, false, err
	}
	switch status {
	case http.StatusOK:
	case http.StatusNotFound, http.StatusGone:
		return SumRecord{}, false, nil
	default:
		return SumRecord{}, false, fmt.Errorf("checksum database %s: HTTP %d", url, status)
	}
	var rec SumRecord
	for _, line := range strings.Split(string(body), "\n") {
		f := strings.Fields(line)
		if len(f) != 3 || f[0] != path {
			continue
		}
		switch f[1] {
		case version:
			rec.Hash = f[2]
		case version + "/go.mod":
			rec.GoModHash = f[2]
		}
	}
	if rec.GoModHash == "" {
		return SumRecord{}, false, fmt.Errorf("checksum database %s: no record for %s %s in a 200 response", url, path, version)
	}
	return rec, true, nil
}

// HTTPProxy queries a module proxy's .info endpoint.
type HTTPProxy struct {
	BaseURL  string
	Client   *http.Client
	Attempts int
}

func (p HTTPProxy) Info(ctx context.Context, path, version string) (ModuleInfo, error) {
	url := strings.TrimRight(p.BaseURL, "/") + "/" + EscapePath(path) + "/@v/" + EscapePath(version) + ".info"
	status, body, err := get(ctx, p.Client, url, p.Attempts)
	if err != nil {
		return ModuleInfo{}, err
	}
	if status != http.StatusOK {
		return ModuleInfo{}, fmt.Errorf("module proxy %s: HTTP %d", url, status)
	}
	var info ModuleInfo
	if err := json.Unmarshal(body, &info); err != nil {
		return ModuleInfo{}, fmt.Errorf("module proxy %s: %w", url, err)
	}
	return info, nil
}

func get(ctx context.Context, c *http.Client, url string, attempts int) (int, []byte, error) {
	if c == nil {
		c = http.DefaultClient
	}
	if attempts <= 0 {
		attempts = 3
	}
	var lastErr error
	for i := 0; i < attempts; i++ {
		if i > 0 {
			select {
			case <-ctx.Done():
				return 0, nil, ctx.Err()
			case <-time.After(time.Duration(i) * time.Second):
			}
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return 0, nil, err
		}
		resp, err := c.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
		_ = resp.Body.Close()
		if err != nil {
			lastErr = err
			continue
		}
		if resp.StatusCode >= 500 {
			lastErr = fmt.Errorf("%s: HTTP %d", url, resp.StatusCode)
			continue
		}
		return resp.StatusCode, body, nil
	}
	return 0, nil, lastErr
}

// ModuleRow is one line of the report.
type ModuleRow struct {
	Change    ModuleChange
	Published time.Time // zero: unknown
	Source    string
	Age       time.Duration
}

// Young reports whether the row is bold: published under YoungAge ago, or of
// unknown age (which deserves the same second look).
func (r ModuleRow) Young() bool { return r.Published.IsZero() || r.Age < YoungAge }

// Report is the guard's verdict and its evidence.
type Report struct {
	Findings []Finding
	Modules  []ModuleRow
}

// Failed reports whether the gate fails.
func (r Report) Failed() bool { return len(r.Findings) > 0 }

// Checker runs the policy against the network services.
type Checker struct {
	SumDB SumDB
	Proxy Proxy
	Now   func() time.Time
}

// Check compares head with base. An error means the verdict could not be
// reached (the checksum database was unreachable), not that it failed.
func (c Checker) Check(ctx context.Context, base, head GoMod, sum GoSum) (Report, error) {
	now := time.Now
	if c.Now != nil {
		now = c.Now
	}
	rep := Report{Findings: CheckReplaces(base, head)}
	for _, ch := range DiffRequires(base, head) {
		id := ch.Path + "@" + ch.NewVersion
		rec, found, err := c.SumDB.Lookup(ctx, ch.Path, ch.NewVersion)
		if err != nil {
			return Report{}, err
		}
		if !found {
			rep.Findings = append(rep.Findings, Finding{Kind: FindingNotInSumDB, Module: id,
				Detail: "sum.golang.org has no record of this module version"})
		} else {
			for key, want := range map[string]string{
				ch.Path + " " + ch.NewVersion:             rec.Hash,
				ch.Path + " " + ch.NewVersion + "/go.mod": rec.GoModHash,
			} {
				if got, ok := sum[key]; ok && want != "" && got != want {
					rep.Findings = append(rep.Findings, Finding{Kind: FindingSumMismatch, Module: id,
						Detail: fmt.Sprintf("go.sum has %s for %q, sum.golang.org has %s", got, key, want)})
				}
			}
		}
		row := ModuleRow{Change: ch, Source: "unknown"}
		if info, err := c.Proxy.Info(ctx, ch.Path, ch.NewVersion); err == nil && !info.Time.IsZero() {
			row.Published = info.Time
			row.Age = now().Sub(info.Time)
			row.Source = "proxy.golang.org (no VCS origin recorded)"
			if info.Origin != nil && info.Origin.URL != "" {
				row.Source = info.Origin.URL
			}
		}
		rep.Modules = append(rep.Modules, row)
	}
	sort.SliceStable(rep.Findings, func(i, j int) bool {
		if rep.Findings[i].Kind != rep.Findings[j].Kind {
			return rep.Findings[i].Kind < rep.Findings[j].Kind
		}
		return rep.Findings[i].Module < rep.Findings[j].Module
	})
	return rep, nil
}

func cell(s string) string {
	return strings.NewReplacer("|", `\|`, "\n", " ", "\r", " ").Replace(s)
}

func age(r ModuleRow) string {
	if r.Published.IsZero() {
		return "unknown"
	}
	d := int(r.Age.Hours() / 24)
	if d == 1 {
		return "1 day"
	}
	return fmt.Sprintf("%d days", d)
}

// RenderMarkdown renders the report for the job summary and the sticky PR
// comment.
func RenderMarkdown(rep Report) string {
	var b strings.Builder
	b.WriteString(Marker + "\n### deps-guard: Go dependency changes\n\n")
	if rep.Failed() {
		fmt.Fprintf(&b, "**Fails: %d finding(s).** A new or changed `replace`, or a module that "+
			"sum.golang.org does not know, is a hard fail with no label. The only override is a "+
			"code-owner approval of this PR (#2649, decision 4).\n\n", len(rep.Findings))
		b.WriteString("| Rule | Module | Detail |\n|---|---|---|\n")
		for _, f := range rep.Findings {
			fmt.Fprintf(&b, "| %s | `%s` | %s |\n", f.Kind, cell(f.Module), cell(f.Detail))
		}
		b.WriteString("\n")
	} else {
		b.WriteString("**Passes:** no new or changed `replace`, and every new or changed module is on sum.golang.org with matching hashes.\n\n")
	}
	bold := func(young bool, s string) string {
		if young {
			return "**" + s + "**"
		}
		return s
	}
	var added, bumped []ModuleRow
	for _, r := range rep.Modules {
		if r.Change.Added() {
			added = append(added, r)
		} else {
			bumped = append(bumped, r)
		}
	}
	if len(added) == 0 && len(bumped) == 0 {
		b.WriteString("No new or changed modules in go.mod.\n")
		return b.String()
	}
	if len(added) > 0 {
		b.WriteString("#### New modules\n\n| Module | Change | Version | Age | Source |\n|---|---|---|---|---|\n")
		for _, r := range added {
			y := r.Young()
			change := "added"
			if r.Change.Indirect {
				change = "added (indirect)"
			}
			fmt.Fprintf(&b, "| %s | %s | %s | %s | %s |\n",
				bold(y, "`"+cell(r.Change.Path)+"`"), bold(y, change), bold(y, cell(r.Change.NewVersion)),
				bold(y, age(r)), bold(y, cell(r.Source)))
		}
		b.WriteString("\n")
	}
	if len(bumped) > 0 {
		b.WriteString("#### Version changes\n\n| Module | Version | Age | Source |\n|---|---|---|---|\n")
		for _, r := range bumped {
			y := r.Young()
			fmt.Fprintf(&b, "| %s | %s | %s | %s |\n",
				bold(y, "`"+cell(r.Change.Path)+"`"), bold(y, cell(r.Change.OldVersion)+" → "+cell(r.Change.NewVersion)),
				bold(y, age(r)), bold(y, cell(r.Source)))
		}
		b.WriteString("\n")
	}
	b.WriteString("Age is from the module proxy's publication timestamp. Rows in **bold** were published less than 14 days ago, or their age is unknown.\n")
	return b.String()
}
