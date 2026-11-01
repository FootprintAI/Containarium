package backup

import (
	"archive/tar"
	"bufio"
	"bytes"
	"cmp"
	"compress/gzip"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"slices"
	"strings"

	"filippo.io/age"
)

// Whole-box restore (#3357, remainder of #2801): a BOX record is decrypted,
// checked against its manifest and streamed into a new box through the
// Incus import seam (#3072). See docs/architecture/container-snapshots.md,
// "Whole-box restore".

// ErrNotBoxBackup is a restore-as-a-box of a record that is not a whole-box
// backup.
var ErrNotBoxBackup = errors.New("not a whole-box backup")

// ErrBoxRestoreUnavailable means this daemon cannot import a box at all.
var ErrBoxRestoreUnavailable = errors.New("whole-box restore is not available on this daemon (no Incus import)")

// ErrBoxRestoreTargetExists refuses a restore into a box that exists when
// the caller did not ask to replace it.
var ErrBoxRestoreTargetExists = errors.New("the restore target box already exists (pass force to replace a stopped box)")

// ErrBoxRestoreTargetRunning refuses a restore into a box that is not
// stopped, with or without force: the caller stops it first.
var ErrBoxRestoreTargetRunning = errors.New("the restore target box is running (stop it first; force never replaces a running box)")

// ErrBoxRestoreInProgress means the target box is already being restored
// into or backed up. Refused, not queued, like a second backup (#3116).
var ErrBoxRestoreInProgress = errors.New("the restore target box is busy with another whole-box backup or restore")

// ErrBoxBackupKey is a restore whose age identity is missing, malformed or
// not one the backup was encrypted to. The identity itself is never part of
// the error.
var ErrBoxBackupKey = errors.New("the age identity is missing, malformed, or does not open this backup")

// ErrBoxBackupCorrupt is a backup whose stored bytes or content fail an
// integrity check: the recorded checksum, the age authentication, the
// archive format, or the manifest's digests.
var ErrBoxBackupCorrupt = errors.New("the whole-box backup failed its integrity check")

// BoxState is what a restore needs to know about a box name.
type BoxState int

const (
	// BoxAbsent: no instance by that name.
	BoxAbsent BoxState = iota
	// BoxStopped: the instance exists and is stopped, so force may replace it.
	BoxStopped
	// BoxActive: the instance exists and is not stopped (running, frozen,
	// starting). Never replaced.
	BoxActive
)

func (s BoxState) String() string {
	switch s {
	case BoxAbsent:
		return "absent"
	case BoxStopped:
		return "stopped"
	case BoxActive:
		return "active"
	default:
		return fmt.Sprintf("BoxState(%d)", int(s))
	}
}

// BoxRestoreOps is what a whole-box restore needs from the container layer,
// on top of BoxOps. Names are Incus instance names.
type BoxRestoreOps interface {
	// BoxState reports whether the instance exists and whether it is stopped.
	BoxState(containerName string) (BoxState, error)
	// ImportBox creates a new, stopped instance from an Incus backup tarball
	// read from archive, streaming it. It refuses an existing name.
	ImportBox(containerName string, archive io.Reader) error
	// RenameBox renames a stopped instance.
	RenameBox(from, to string) error
	// DeleteBox deletes a stopped instance.
	DeleteBox(containerName string) error
}

// BoxRestoreOptions parameterizes a whole-box restore.
type BoxRestoreOptions struct {
	ID string
	// TargetContainer is the Incus instance to restore into
	// ("<box>-container"). The caller resolves the default name and
	// authorizes it.
	TargetContainer string
	// Force replaces a stopped TargetContainer. A running one is refused.
	Force bool
	// AgeIdentity opens the backup. Used for this call only: never stored,
	// logged, or put in an error.
	AgeIdentity string
}

// boxRestoreStagingPrefix names the instance a restore imports into before
// it takes the target's name. It does not end in "-container", so it is
// never read as a tenant's box.
const boxRestoreStagingPrefix = "containarium-restore-"

// maxBoxManifestBytes bounds the manifest entry a restore reads into
// memory. At about a hundred bytes per file this is several hundred
// thousand files of headroom over any box the 256 GiB cap admits in practice.
const maxBoxManifestBytes = 256 << 20

// RestoreBox restores a whole-box backup into a new box.
//
// Order: every refusal (record, size, key, target state, per-box claim,
// checksum, age header) comes before the first byte reaches Incus. The
// archive is then decrypted and streamed into an instance under a unique
// staging name, its entries digested on the way; Incus sees the end of the
// stream only once the manifest at its end has matched, so a mismatch fails
// the import. Any failure from there deletes the staging instance, so no
// partial box is left. Only a fully imported box replaces a stopped target
// (force): the old one is deleted, and the staging instance renamed to the
// target's name.
func (m *Manager) RestoreBox(opts BoxRestoreOptions) error {
	if m.boxRestore == nil {
		return ErrBoxRestoreUnavailable
	}
	target := strings.TrimSpace(opts.TargetContainer)
	if target == "" {
		return errors.New("restore target box is required")
	}
	r, err := m.Get(opts.ID)
	if err != nil {
		return err
	}
	if r.Engine != EngineBox {
		return fmt.Errorf("%w: backup %s is a database backup; restore it with RestoreBackup", ErrNotBoxBackup, r.ID)
	}
	if r.SizeBytes < 0 || r.SizeBytes > m.maxBoxBytes {
		return fmt.Errorf("%w: recorded size %d (limit %d)", ErrDumpTooLarge, r.SizeBytes, m.maxBoxBytes)
	}
	if !r.Encrypted {
		return fmt.Errorf("%w: backup %s is recorded as plaintext, which a whole-box backup never is", ErrBoxBackupCorrupt, r.ID)
	}
	identity, err := age.ParseX25519Identity(strings.TrimSpace(opts.AgeIdentity))
	if err != nil {
		// The parse error can quote the input; it is dropped.
		return fmt.Errorf("restore %s: %w", r.ID, ErrBoxBackupKey)
	}

	release, err := m.claimBox(target)
	if err != nil {
		return err
	}
	defer release()
	state, err := m.boxRestore.BoxState(target)
	if err != nil {
		return fmt.Errorf("read state of %s: %w", target, err)
	}
	if err := refuseTarget(target, state, opts.Force); err != nil {
		return err
	}

	dump, err := m.fetchDumpLimit(r, m.maxBoxBytes)
	if err != nil {
		if errors.Is(err, ErrDumpIntegrity) {
			return fmt.Errorf("%w: %v", ErrBoxBackupCorrupt, err)
		}
		return err
	}
	defer func() { _ = dump.Close() }()
	plain, err := age.Decrypt(dump, identity)
	if err != nil {
		var noMatch *age.NoIdentityMatchError
		if errors.As(err, &noMatch) {
			return fmt.Errorf("restore %s: %w", r.ID, ErrBoxBackupKey)
		}
		return fmt.Errorf("%w: age header: %v", ErrBoxBackupCorrupt, err)
	}

	staging, err := boxRestoreStagingName()
	if err != nil {
		return err
	}
	if err := m.importBoxStream(staging, decryptReader{plain}); err != nil {
		return fmt.Errorf("restore %s into %s: %w", r.ID, target, err)
	}

	if state == BoxStopped {
		// Re-read under the claim: the target may have been started while
		// the import ran.
		now, err := m.boxRestore.BoxState(target)
		if err == nil {
			err = refuseTarget(target, now, true)
		}
		if err == nil && now != BoxAbsent {
			err = m.boxRestore.DeleteBox(target)
		}
		if err != nil {
			m.removeStaging(staging)
			return fmt.Errorf("restore %s: replace %s: %w", r.ID, target, err)
		}
	}
	if err := m.boxRestore.RenameBox(staging, target); err != nil {
		// The restored box is complete; it is kept under the staging name
		// rather than lost, and the error says where it is.
		return fmt.Errorf("restore %s: the box was restored as %s but could not be renamed to %s: %w", r.ID, staging, target, err)
	}
	return nil
}

// refuseTarget applies the target rules: an existing box needs force, and a
// box that is not stopped is never replaced.
func refuseTarget(target string, state BoxState, force bool) error {
	switch state {
	case BoxAbsent:
		return nil
	case BoxStopped:
		if !force {
			return fmt.Errorf("%w: %s", ErrBoxRestoreTargetExists, target)
		}
		return nil
	default:
		return fmt.Errorf("%w: %s", ErrBoxRestoreTargetRunning, target)
	}
}

// importBoxStream runs the restore filter into ImportBox through a pipe.
// On any failure the staging instance is removed, whatever state Incus left
// it in.
func (m *Manager) importBoxStream(staging string, src io.Reader) error {
	pr, pw := io.Pipe()
	done := make(chan error, 1)
	go func() {
		err := restoreBoxArchive(src, pw, m.maxBoxBytes)
		pw.CloseWithError(err)
		done <- err
	}()
	importErr := m.boxRestore.ImportBox(staging, pr)
	// Unblock the filter if the import stopped reading first.
	_ = pr.CloseWithError(errors.New("import stopped"))
	filterErr := <-done
	if filterErr == nil && importErr == nil {
		return nil
	}
	m.removeStaging(staging)
	// The archive's own failure is the cause unless the filter only saw the
	// pipe close under it.
	if filterErr != nil && (importErr == nil || isArchiveFailure(filterErr)) {
		return filterErr
	}
	return fmt.Errorf("import: %w", importErr)
}

func isArchiveFailure(err error) bool {
	return errors.Is(err, ErrBoxBackupCorrupt) || errors.Is(err, ErrDumpTooLarge)
}

// removeStaging deletes a staging instance if Incus created it. Failure is
// logged: the name is unique to this restore, so nothing else uses it.
func (m *Manager) removeStaging(name string) {
	state, err := m.boxRestore.BoxState(name)
	if err == nil && state == BoxAbsent {
		return
	}
	if err := m.boxRestore.DeleteBox(name); err != nil {
		log.Printf("[backup] whole-box restore: could not remove partial box %s: %v (delete it by hand)", name, err)
	}
}

func boxRestoreStagingName() (string, error) {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return boxRestoreStagingPrefix + hex.EncodeToString(b), nil
}

// claimBox takes the per-box claim a whole-box backup takes (#3116), with
// no space reservation, for a restore into name.
func (m *Manager) claimBox(name string) (release func(), err error) {
	c := &m.boxClaims
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, busy := c.inFlight[name]; busy {
		return nil, fmt.Errorf("%w: %s (retry when it finishes)", ErrBoxRestoreInProgress, name)
	}
	if c.inFlight == nil {
		c.inFlight = map[string]*boxClaim{}
	}
	claim := &boxClaim{box: name, need: map[uint64]uint64{}}
	c.inFlight[name] = claim
	return func() { m.releaseBoxClaim(claim) }, nil
}

// corrupt wraps a content failure of the archive in ErrBoxBackupCorrupt.
func corrupt(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrBoxBackupCorrupt, fmt.Sprintf(format, args...))
}

// restoreBoxArchive copies a decrypted whole-box archive from src to dst,
// gzip in and gzip out, re-emitting every entry unchanged (headers, PAX
// records, hard links) except the manifest, which Incus does not need. It
// digests every regular file as create did and, at the manifest, compares
// the lot. dst receives the end of the archive only after that comparison
// has passed, so a reader importing dst never sees a complete archive whose
// content differs from its manifest.
//
// Memory is independent of the archive's size, as for the create filter:
// the digests kept for the comparison grow with the number of files.
func restoreBoxArchive(src io.Reader, dst io.Writer, limit int64) error {
	br := bufio.NewReader(src)
	magic, err := br.Peek(2)
	if err != nil {
		return archiveReadErr(err)
	}
	if !bytes.Equal(magic, []byte{0x1f, 0x8b}) {
		return corrupt("archive is not gzip-compressed")
	}
	gzr, err := gzip.NewReader(br)
	if err != nil {
		return archiveReadErr(err)
	}
	plain := &boundedReader{r: gzr, limit: limit}
	tr := tar.NewReader(plain)
	gzw, err := gzip.NewWriterLevel(dst, gzip.BestSpeed)
	if err != nil {
		return err
	}
	tw := tar.NewWriter(gzw)

	var got BoxManifest
	var want *BoxManifest
	h := sha256.New()
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return archiveReadErr(err)
		}
		name := strings.TrimPrefix(hdr.Name, "./")
		if want != nil {
			return corrupt("entry %s follows the manifest, which must be last", name)
		}
		if name == BoxManifestPath {
			if hdr.Typeflag != tar.TypeReg || hdr.Size > maxBoxManifestBytes {
				return corrupt("manifest entry is not a regular file of at most %d bytes", maxBoxManifestBytes)
			}
			want = &BoxManifest{}
			if err := json.NewDecoder(io.LimitReader(tr, hdr.Size)).Decode(want); err != nil {
				return corrupt("manifest: %v", err)
			}
			continue
		}
		rel, inRootfs := strings.CutPrefix(name, boxRootfsPrefix)
		if hdr.Typeflag == tar.TypeLink {
			target, targetInRootfs := strings.CutPrefix(strings.TrimPrefix(hdr.Linkname, "./"), boxRootfsPrefix)
			if inRootfs && targetInRootfs {
				got.Links = append(got.Links, BoxManifestLink{Path: "/" + rel, Target: "/" + target})
			}
		}
		if hdr.Typeflag != tar.TypeReg {
			if err := tw.WriteHeader(hdr); err != nil {
				return fmt.Errorf("write %s: %w", name, err)
			}
			continue
		}
		entry, err := copyEntry(tw, h, hdr, tr)
		if err != nil {
			if isArchiveFailure(err) || errors.Is(err, io.ErrUnexpectedEOF) {
				return corrupt("%v", err)
			}
			return err
		}
		if inRootfs {
			entry.Path = "/" + rel
			got.Files = append(got.Files, entry)
		} else {
			entry.Path = name
			got.Config = append(got.Config, entry)
		}
	}
	trailing, err := io.CopyN(zeroOnly{}, plain, maxBoxTrailingBytes+1)
	switch {
	case errors.Is(err, errNonZeroTrailing) || trailing > maxBoxTrailingBytes:
		return corrupt("trailing data after the end of the archive")
	case err != nil && !errors.Is(err, io.EOF):
		return archiveReadErr(err)
	}
	if want == nil {
		return corrupt("the archive has no manifest (%s)", BoxManifestPath)
	}
	if err := matchManifest(want, &got); err != nil {
		return err
	}
	if err := tw.Close(); err != nil {
		return err
	}
	return gzw.Close()
}

// archiveReadErr classifies a failure reading the decrypted archive: a
// failed age chunk, a truncated or malformed gzip or tar stream, or the
// size cap. Each is the backup's fault, never the import's.
func archiveReadErr(err error) error {
	if errors.Is(err, ErrDumpTooLarge) {
		return err
	}
	var de *decryptionError
	if errors.As(err, &de) {
		return corrupt("age decrypt: %v", de.err)
	}
	return corrupt("read archive: %v", err)
}

// matchManifest compares what the archive carried with what its manifest
// says it carried: the same files (path, size, digest), config entries and
// hard links, as multisets.
func matchManifest(want, got *BoxManifest) error {
	if want.Version != boxManifestVersion {
		return corrupt("manifest version %d, this daemon reads %d", want.Version, boxManifestVersion)
	}
	if err := matchFiles("file", want.Files, got.Files); err != nil {
		return err
	}
	if err := matchFiles("config entry", want.Config, got.Config); err != nil {
		return err
	}
	byLink := func(a, b BoxManifestLink) int {
		return cmp.Or(cmp.Compare(a.Path, b.Path), cmp.Compare(a.Target, b.Target))
	}
	slices.SortFunc(want.Links, byLink)
	slices.SortFunc(got.Links, byLink)
	if !slices.Equal(want.Links, got.Links) {
		return corrupt("hard links differ from the manifest (%d listed, %d in the archive)", len(want.Links), len(got.Links))
	}
	return nil
}

func matchFiles(kind string, want, got []BoxManifestFile) error {
	byFile := func(a, b BoxManifestFile) int {
		return cmp.Or(cmp.Compare(a.Path, b.Path), cmp.Compare(a.SHA256, b.SHA256), cmp.Compare(a.Size, b.Size))
	}
	slices.SortFunc(want, byFile)
	slices.SortFunc(got, byFile)
	for i := 0; i < len(want) || i < len(got); i++ {
		switch {
		case i >= len(got):
			return corrupt("%s %s is in the manifest but not in the archive", kind, want[i].Path)
		case i >= len(want):
			return corrupt("%s %s is in the archive but not in the manifest", kind, got[i].Path)
		case want[i] != got[i]:
			return corrupt("%s %s does not match the manifest", kind, cmp.Or(got[i].Path, want[i].Path))
		}
	}
	return nil
}
