package backup

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	"filippo.io/age"
)

// Verify-by-restore of a whole-box backup (#2802, slice 3 of #2372): the
// record is decrypted and restored into a scratch box, the restored box is
// read back and every regular file compared with the manifest written at
// create time, and the scratch box is deleted. See
// docs/architecture/container-snapshots.md, "Whole-box verify".

// VerificationIncomplete is a restore test that ran out of time before it
// compared every file (#2809, Q-C). It is never a pass.
const VerificationIncomplete VerificationResult = "incomplete"

// DefaultBoxVerifyTimeLimit caps the comparison of a restored box with its
// manifest (#2809, Q-C).
const DefaultBoxVerifyTimeLimit = 15 * time.Minute

// boxVerifyScratchPrefix names the scratch box a verify restores into. It
// does not end in "-container", so it is never read as a tenant's box, and
// it differs from a restore's staging prefix, so a leaked one says which
// operation left it.
const boxVerifyScratchPrefix = "containarium-verify-"

// errBoxVerifyTimeLimit stops the comparison at the time cap.
var errBoxVerifyTimeLimit = errors.New("time limit reached")

// WithBoxVerifyTimeLimit overrides the 15-minute cap on comparing a
// restored box with its manifest. Non-positive values keep the default.
func WithBoxVerifyTimeLimit(d time.Duration) Option {
	return func(m *Manager) {
		if d > 0 {
			m.boxVerifyLimit = d
		}
	}
}

// BoxVerifyOptions parameterizes a whole-box restore test.
type BoxVerifyOptions struct {
	ID string
	// VerifiedBy is the authenticated subject, for the audit record.
	VerifiedBy string
	// AgeIdentity opens the backup, as for RestoreBox. Used for this call
	// only: never stored, logged, or put in a result.
	AgeIdentity string
}

// VerifyBox restore-tests a whole-box backup and records the outcome on the
// record, like Verify does for a database dump. A backup that fails a check
// (checksum, decryption, archive or manifest, the restored box's files) is a
// FAILED result, not an error; a comparison cut short by the time cap is
// INCOMPLETE. An error means the test could not run at all. The scratch box
// is deleted on every path once it may exist, and a scratch box that cannot
// be deleted fails the verification.
func (m *Manager) VerifyBox(opts BoxVerifyOptions) (*Verification, error) {
	if m.box == nil || m.boxRestore == nil {
		return nil, ErrBoxRestoreUnavailable
	}
	r, err := m.Get(opts.ID)
	if err != nil {
		return nil, err
	}
	if r.Engine != EngineBox {
		return nil, fmt.Errorf("%w: backup %s is a database backup; verify it against a target database", ErrNotBoxBackup, r.ID)
	}
	if strings.TrimSpace(opts.AgeIdentity) == "" {
		return nil, fmt.Errorf("backup %s is encrypted: supply the age identity that opens it to verify (the platform holds no decryption key)", r.ID)
	}
	scratch, err := boxRestoreStagingName()
	if err != nil {
		return nil, err
	}
	scratch = boxVerifyScratchPrefix + strings.TrimPrefix(scratch, boxRestoreStagingPrefix)

	started := m.now()
	v := &Verification{Result: VerificationPassed, TargetContainer: scratch, VerifiedBy: opts.VerifiedBy}
	m.restoreAndCompare(r, opts.AgeIdentity, scratch, v)

	m.removeStaging(scratch)
	if state, err := m.boxRestore.BoxState(scratch); err != nil || state != BoxAbsent {
		v.fail("cleanup", fmt.Sprintf("could not delete scratch box %s (delete it by hand): state %s, %v", scratch, state, err))
	} else {
		v.pass("cleanup", "deleted scratch box "+scratch)
	}
	return m.commitVerification(r, v, started)
}

// restoreAndCompare runs the checks in order and stops at the first that
// fails.
func (m *Manager) restoreAndCompare(r *Record, ageIdentity, scratch string, v *Verification) {
	if !r.Encrypted || r.SizeBytes < 0 || r.SizeBytes > m.maxBoxBytes {
		v.fail("integrity", fmt.Sprintf("record is not an encrypted whole-box backup within the %d-byte cap (encrypted %t, size %d)", m.maxBoxBytes, r.Encrypted, r.SizeBytes))
		return
	}
	identity, err := age.ParseX25519Identity(strings.TrimSpace(ageIdentity))
	if err != nil {
		v.fail("decrypt", ErrBoxBackupKey.Error()) // the parse error can quote the input
		return
	}
	dump, err := m.fetchDumpLimit(r, m.maxBoxBytes)
	if err != nil {
		v.fail("integrity", "stored bytes do not match the recorded checksum: "+err.Error())
		return
	}
	defer func() { _ = dump.Close() }()
	v.pass("integrity", fmt.Sprintf("sha256 matches recorded checksum (%d bytes)", dump.size))

	plain, err := age.Decrypt(dump, identity)
	if err != nil {
		var noMatch *age.NoIdentityMatchError
		if errors.As(err, &noMatch) {
			v.fail("decrypt", ErrBoxBackupKey.Error())
		} else {
			v.fail("decrypt", "age header: "+err.Error())
		}
		return
	}
	v.pass("decrypt", "opened with the supplied identity")

	mf, err := m.importBoxStream(scratch, decryptReader{plain})
	if err != nil {
		v.fail("restore", err.Error())
		return
	}
	v.pass("restore", fmt.Sprintf("restored into scratch box %s; the archive matched its manifest", scratch))

	limit := cmpOr(m.boxVerifyLimit, DefaultBoxVerifyTimeLimit)
	checked, total, err := m.compareRestoredBox(scratch, mf, limit)
	switch {
	case errors.Is(err, errBoxVerifyTimeLimit):
		detail := fmt.Sprintf("compared %d of %d files before the %s time limit: partial coverage, not a pass", checked, total, limit)
		v.fail("manifest", detail)
		v.Result = VerificationIncomplete
	case err != nil:
		v.fail("manifest", err.Error())
	default:
		v.pass("manifest", fmt.Sprintf("all %d files of the restored box match the manifest digests", total))
	}
}

func cmpOr(d, def time.Duration) time.Duration {
	if d > 0 {
		return d
	}
	return def
}

// compareRestoredBox exports the restored box and compares every regular
// file (and hard link) of its root filesystem with the manifest: the same
// paths, sizes and SHA-256 digests. Contents of the excluded directories
// are skipped, as at create time. It stops at the time limit.
func (m *Manager) compareRestoredBox(name string, mf *BoxManifest, limit time.Duration) (checked, total int, err error) {
	want := make(map[string]BoxManifestFile, len(mf.Files)+len(mf.Links))
	for _, f := range mf.Files {
		want[f.Path] = f
	}
	for _, l := range mf.Links {
		if f, ok := want[l.Target]; ok {
			f.Path = l.Path
			want[l.Path] = f
		}
	}
	total = len(want)
	deadline := m.now().Add(limit)

	rc, err := m.box.ExportInstance(name)
	if err != nil {
		return 0, total, fmt.Errorf("export the restored box: %w", err)
	}
	defer func() { _ = rc.Close() }()
	gzr, err := gzip.NewReader(rc)
	if err != nil {
		return 0, total, fmt.Errorf("read the restored box: %w", err)
	}
	tr := tar.NewReader(&boundedReader{r: gzr, limit: m.maxBoxBytes})
	seen := map[string]BoxManifestFile{}
	for {
		if m.now().After(deadline) {
			return checked, total, errBoxVerifyTimeLimit
		}
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return checked, total, fmt.Errorf("read the restored box: %w", err)
		}
		rel, ok := strings.CutPrefix(strings.TrimPrefix(hdr.Name, "./"), boxRootfsPrefix)
		path := "/" + rel
		if !ok || boxPathExcluded(path, mf.Excluded) {
			continue
		}
		var got BoxManifestFile
		switch hdr.Typeflag {
		case tar.TypeReg:
			h := sha256.New()
			n, err := io.Copy(h, tr)
			if err != nil {
				return checked, total, fmt.Errorf("read %s from the restored box: %w", path, err)
			}
			got = BoxManifestFile{Size: n, SHA256: hex.EncodeToString(h.Sum(nil))}
		case tar.TypeLink:
			target, _ := strings.CutPrefix(strings.TrimPrefix(hdr.Linkname, "./"), boxRootfsPrefix)
			if got, ok = seen["/"+target]; !ok {
				return checked, total, corrupt("file %s in the restored box links to /%s, which it does not carry", path, target)
			}
		default:
			continue
		}
		got.Path = path
		seen[path] = got
		w, ok := want[path]
		switch {
		case !ok:
			return checked, total, corrupt("file %s is in the restored box but not in the manifest", path)
		case w != got:
			return checked, total, corrupt("file %s in the restored box does not match the manifest", path)
		}
		delete(want, path)
		checked++
	}
	if len(want) > 0 {
		missing := make([]string, 0, len(want))
		for p := range want {
			missing = append(missing, p)
		}
		slices.Sort(missing)
		return checked, total, corrupt("file %s is in the manifest but missing from the restored box (%d missing)", missing[0], len(missing))
	}
	return checked, total, nil
}

// boxPathExcluded reports whether path lies inside one of the excluded
// directories.
func boxPathExcluded(path string, excluded []string) bool {
	for _, d := range excluded {
		if strings.HasPrefix(path, strings.TrimSuffix(d, "/")+"/") {
			return true
		}
	}
	return false
}

func (v *Verification) fail(check, detail string) {
	v.Result = VerificationFailed
	if v.Error == "" {
		v.Error = detail
	}
	v.Checks = append(v.Checks, Check{Name: check, Passed: false, Detail: detail})
}

func (v *Verification) pass(check, detail string) {
	v.Checks = append(v.Checks, Check{Name: check, Passed: true, Detail: detail})
}
