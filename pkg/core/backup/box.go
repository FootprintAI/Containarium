package backup

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"log"
	"os"
	"strings"
	"time"

	"filippo.io/age"
)

// Whole-box backups (#2801, slice 2 of #2372). The box is exported through
// Incus (incus.Backend.ExportInstance, #3072), filtered and digested on the
// way through, encrypted like any other backup, and stored at the usual
// destination. See docs/architecture/container-snapshots.md, "Whole-box
// backups".

// EngineBox marks a whole-box record (BACKUP_ENGINE_BOX on the wire). Such a
// record is restored by importing it as a new box, never by pg_restore.
const EngineBox = "box"

// DefaultMaxBoxBytes is the BOX cap on the stored archive: 256 GiB, separate
// from the 16 GiB database-dump cap (decision of 2026-10-25 on #2801).
const DefaultMaxBoxBytes int64 = 256 << 30

// BoxManifestPath is the archive entry that carries the manifest. It is the
// last entry of the tarball, so it sits inside the encryption with the data
// it describes. A restore strips it before handing the archive to Incus.
const BoxManifestPath = "backup/containarium-manifest.json"

// boxArchiveExt names what a stored whole-box backup is: an age file
// wrapping a gzip tarball. A BOX backup is never plaintext.
const boxArchiveExt = ".box.tar.gz.age"

// boxRootfsPrefix is where an Incus instance backup keeps the root
// filesystem.
const boxRootfsPrefix = "backup/container/rootfs/"

// boxExcludedDirs are the rootfs directories whose contents a whole-box
// backup leaves out (decision of 2026-10-25 on #2800). The directory
// entries themselves are kept, so a restored box still has them with their
// modes.
var boxExcludedDirs = []string{"tmp", "var/tmp", "var/cache", "run"}

// ErrInsufficientSpace is the free-space pre-flight refusing a whole-box
// backup before it starts.
var ErrInsufficientSpace = errors.New("not enough free space for a whole-box backup")

// ErrBoxUnavailable means this daemon cannot export a box at all.
var ErrBoxUnavailable = errors.New("whole-box backup is not available on this daemon (no Incus export)")

// BoxOps is what a whole-box backup needs from the container layer.
type BoxOps interface {
	// ExportInstance streams the instance as an Incus backup tarball. The
	// caller closes the reader.
	ExportInstance(containerName string) (io.ReadCloser, error)
	// BoxDiskUsage reports the bytes the box's root disk uses: the size
	// estimate the free-space pre-flight works from.
	BoxDiskUsage(containerName string) (int64, error)
}

// WithBoxOps enables whole-box backups.
func WithBoxOps(b BoxOps) Option {
	return func(m *Manager) { m.box = b }
}

// WithBoxStagingDirs names directories where Incus stages an export before
// streaming it (on Incus 6.0 LTS, its backups directory). The free-space
// pre-flight counts one copy of the box in each that exists.
func WithBoxStagingDirs(dirs ...string) Option {
	return func(m *Manager) { m.boxStagingDirs = append(m.boxStagingDirs, dirs...) }
}

// WithMaxBoxBytes overrides the 256 GiB BOX cap. Non-positive values keep
// the default; there is no unlimited mode.
func WithMaxBoxBytes(n int64) Option {
	return func(m *Manager) {
		if n > 0 {
			m.maxBoxBytes = n
		}
	}
}

// withFreeSpace replaces the statfs probe (tests).
func withFreeSpace(f func(path string) (diskSpace, error)) Option {
	return func(m *Manager) { m.freeSpace = f }
}

// diskSpace is what the pre-flight needs to know about a directory: free
// bytes for an unprivileged writer, and which filesystem it is on, so two
// staging areas on one filesystem are counted together.
type diskSpace struct {
	Free   uint64
	Device uint64
}

// BoxCreateOptions parameterizes a whole-box backup. The fields mean what
// they mean in CreateOptions, except that KeyMode is required: a BOX
// backup is never plaintext.
type BoxCreateOptions struct {
	Username      string
	ContainerName string
	Destination   Destination
	GCSBucket     string
	AgeRecipient  string
	KeyMode       KeyMode
}

// BoxManifest is written at create time as the archive's last entry
// (decision of 2026-10-25 on #2801), for verify-by-restore (#2802) to
// compare a restored box against.
type BoxManifest struct {
	Version   int       `json:"version"`
	Box       string    `json:"box"`
	CreatedAt time.Time `json:"created_at"`
	// Excluded lists the directories whose contents were left out, as
	// absolute paths inside the box.
	Excluded []string `json:"excluded"`
	// Files are the regular files of the root filesystem, by absolute path
	// inside the box.
	Files []BoxManifestFile `json:"files"`
	// Links are the hard links of the root filesystem.
	Links []BoxManifestLink `json:"links,omitempty"`
	// Config are the regular files outside the root filesystem, by archive
	// path: Incus's index.yaml, and backup.yaml, which carries the box's
	// config and devices.
	Config []BoxManifestFile `json:"config"`
}

// BoxManifestFile is one regular file and its SHA-256.
type BoxManifestFile struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

// BoxManifestLink is one hard link; Target is the file it shares content
// with.
type BoxManifestLink struct {
	Path   string `json:"path"`
	Target string `json:"target"`
}

// boxManifestVersion is the manifest format version.
const boxManifestVersion = 1

func errBoxRecordNotDatabase(id, verb string) error {
	return fmt.Errorf("backup %s is a whole-box backup: it cannot be %s through the database path (whole-box restore is tracked in #2801)", id, verb)
}

// CreateBox backs up a whole box: export, drop the excluded directories'
// contents, digest every regular file into the manifest, encrypt, and
// store. Every refusal precedes the export.
func (m *Manager) CreateBox(opts BoxCreateOptions) (*Record, error) {
	if m.box == nil {
		return nil, ErrBoxUnavailable
	}
	if opts.ContainerName == "" {
		return nil, fmt.Errorf("container name is required")
	}
	if opts.KeyMode == "" {
		return nil, fmt.Errorf("a whole-box backup cannot be plaintext: name a key mode (managed, age_recipient or both)")
	}
	if opts.AgeRecipient != "" {
		if _, err := parseRecipient(opts.AgeRecipient); err != nil {
			return nil, err
		}
	}
	mode, err := m.resolveKeyMode(opts.KeyMode, opts.AgeRecipient)
	if err != nil {
		return nil, err
	}
	if err := m.checkDestination(opts.Destination, opts.GCSBucket); err != nil {
		return nil, err
	}
	id := fmt.Sprintf("%s-box-%s", opts.Username, m.now().UTC().Format("20060102T150405Z"))
	if err := validateBackupID(id); err != nil {
		return nil, fmt.Errorf("cannot derive a safe backup id: %w", err)
	}
	if _, err := os.Stat(m.sidecarPath(id)); err == nil {
		return nil, fmt.Errorf("backup %s already exists: retry in a second", id)
	}
	if err := m.boxPreflight(opts.ContainerName); err != nil {
		return nil, err
	}
	plan, err := m.planEncryption(mode, opts.AgeRecipient)
	if err != nil {
		return nil, err
	}

	export, err := m.box.ExportInstance(opts.ContainerName)
	if err != nil {
		return nil, fmt.Errorf("export %s: %w", opts.ContainerName, err)
	}
	// The filter runs in its own goroutine, writing into a pipe that
	// stageDump reads from. Closing the read end on a staging failure
	// stops the filter; waiting on done keeps the export open until the
	// filter is off it.
	pr, pw := io.Pipe()
	done := make(chan error, 1)
	go func() {
		err := filterBoxArchive(export, pw, opts.ContainerName, m.now().UTC(), m.maxBoxBytes, m.dir)
		pw.CloseWithError(err)
		done <- err
	}()
	localPath, size, checksum, stageErr := m.stageDump(pr, id, boxArchiveExt, plan.recipients, m.maxBoxBytes)
	// Unblock the filter whichever side stopped first: closing the read end
	// fails its next write, and closing the export fails its next read.
	_ = pr.CloseWithError(errors.New("staging stopped"))
	closeErr := export.Close()
	filterErr := <-done
	if stageErr != nil {
		// The filter's own error is the cause unless staging hit the cap,
		// in which case the filter only saw the pipe close.
		if filterErr != nil && !errors.Is(stageErr, ErrDumpTooLarge) {
			return nil, fmt.Errorf("export %s: %w", opts.ContainerName, filterErr)
		}
		return nil, fmt.Errorf("whole-box backup of %s: %w", opts.ContainerName, stageErr)
	}
	// Staging read the filter's output to EOF, so the filter succeeded: any
	// filter error would have reached stageDump through the pipe. A failure
	// to close the export (on Incus 6.0 LTS, to delete the stored backup it
	// streamed from) does not make the archive incomplete; Incus expires
	// that backup on its own.
	if closeErr != nil {
		log.Printf("[backup] whole-box backup %s: closing the export of %s: %v", id, opts.ContainerName, closeErr)
	}

	record := &Record{
		ID:          id,
		Username:    opts.Username,
		Database:    opts.ContainerName,
		CreatedAt:   m.now().UTC(),
		SizeBytes:   size,
		SHA256:      checksum,
		Destination: opts.Destination,
		Engine:      EngineBox,
	}
	plan.apply(record)
	if err := m.commit(record, localPath, opts.GCSBucket, boxArchiveExt); err != nil {
		return nil, err
	}
	return record, nil
}

// boxPreflight refuses a backup that cannot fit before the export starts.
//
// The estimate is the box's disk usage. Incus may stage one compressed copy
// in each of boxStagingDirs (on 6.0 LTS, before the first byte streams),
// and we stage the encrypted archive in m.dir, which the cap bounds. The
// compressed sizes are not known up front, so each staging area is asked
// for the uncompressed usage: conservative, never optimistic. Two areas on
// one filesystem are counted together.
func (m *Manager) boxPreflight(containerName string) error {
	usage, err := m.box.BoxDiskUsage(containerName)
	if err != nil {
		return fmt.Errorf("read disk usage of %s for the free-space pre-flight: %w", containerName, err)
	}
	if usage <= 0 {
		return fmt.Errorf("disk usage of %s is unknown, so the free-space pre-flight cannot run", containerName)
	}
	if err := os.MkdirAll(m.dir, 0o700); err != nil {
		return err
	}
	ours := min(usage, m.maxBoxBytes)
	type area struct {
		need  uint64
		free  uint64
		paths []string
	}
	byDevice := map[uint64]*area{}
	var order []uint64
	add := func(path string, need int64) error {
		ds, err := m.freeSpace(path)
		if err != nil {
			return fmt.Errorf("free-space pre-flight on %s: %w", path, err)
		}
		a, ok := byDevice[ds.Device]
		if !ok {
			a = &area{free: ds.Free}
			byDevice[ds.Device] = a
			order = append(order, ds.Device)
		}
		a.need += uint64(need) // #nosec G115 -- need is a positive byte count
		a.paths = append(a.paths, path)
		return nil
	}
	if err := add(m.dir, ours); err != nil {
		return err
	}
	for _, dir := range m.boxStagingDirs {
		if fi, err := os.Stat(dir); err != nil || !fi.IsDir() {
			log.Printf("[backup] free-space pre-flight: Incus staging dir %s not found; not counted", dir)
			continue
		}
		if err := add(dir, usage); err != nil {
			return err
		}
	}
	for _, dev := range order {
		a := byDevice[dev]
		if a.free < a.need {
			return fmt.Errorf("%w: %s needs %d bytes free for a box using %d bytes, has %d",
				ErrInsufficientSpace, strings.Join(a.paths, " and "), a.need, usage, a.free)
		}
	}
	return nil
}

// filterBoxArchive copies an Incus instance backup from src to dst, gzip in
// and gzip out. On the way it drops the contents of the excluded
// directories (keeping the directory entries), digests every regular file,
// and appends the manifest as the last entry. Every other entry, including
// its PAX records (xattrs, file capabilities), is re-emitted unchanged.
//
// Memory is independent of the archive's size: file contents stream
// through. The manifest itself is held until the end, so it grows with the
// number of files (about a hundred bytes each), not with their size.
//
// limit bounds the uncompressed stream as well as (in stageDump) the stored
// archive, as DefaultMaxDumpBytes does for a dump: a box of zeros or a
// sparse file compresses to almost nothing and must not be decompressed
// without bound.
//
// A hard link at a kept path whose target is excluded keeps its content:
// the content of every dropped regular file is set aside in spillDir,
// encrypted to a key that exists only in memory for this call, and the
// first kept name is re-emitted as a regular file from it. Later kept
// names link to that one. The spill is deleted on return. It holds at most
// the excluded content, which the box's disk usage (what the free-space
// pre-flight counts) already includes.
func filterBoxArchive(src io.Reader, dst io.Writer, box string, now time.Time, limit int64, spillDir string) error {
	br := bufio.NewReader(src)
	magic, err := br.Peek(2)
	if err != nil {
		return fmt.Errorf("read export: %w", err)
	}
	if !bytes.Equal(magic, []byte{0x1f, 0x8b}) {
		return fmt.Errorf("export is not gzip-compressed (magic %x): a whole-box backup needs the Incus backup compression to be gzip", magic)
	}
	gzr, err := gzip.NewReader(br)
	if err != nil {
		return fmt.Errorf("read export: %w", err)
	}
	plain := &boundedReader{r: gzr, limit: limit}
	tr := tar.NewReader(plain)
	// BestSpeed: the stream is recompressed on the daemon, single-threaded,
	// on the backup's critical path; storage is cheaper than hours.
	gzw, err := gzip.NewWriterLevel(dst, gzip.BestSpeed)
	if err != nil {
		return err
	}
	tw := tar.NewWriter(gzw)

	mf := BoxManifest{Version: boxManifestVersion, Box: box, CreatedAt: now, Files: []BoxManifestFile{}, Config: []BoxManifestFile{}}
	for _, d := range boxExcludedDirs {
		mf.Excluded = append(mf.Excluded, "/"+d)
	}
	h := sha256.New()
	spill := &boxSpill{dir: spillDir}
	defer spill.close()
	promotedLinks := map[string]string{}
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("read export: %w", err)
		}
		name := strings.TrimPrefix(hdr.Name, "./")
		if name == BoxManifestPath {
			return fmt.Errorf("export already carries an entry at the manifest path %s", BoxManifestPath)
		}
		rel, inRootfs := strings.CutPrefix(name, boxRootfsPrefix)
		if inRootfs && boxExcluded(rel) {
			// A dropped regular file may have another name outside the
			// excluded directories, carried later in the tar as a hard
			// link to this one. Keep its content aside until the end.
			if hdr.Typeflag == tar.TypeReg {
				if err := spill.add(name, hdr, io.LimitReader(tr, hdr.Size)); err != nil {
					return fmt.Errorf("set aside %s: %w", name, err)
				}
			}
			continue
		}
		if hdr.Typeflag == tar.TypeLink {
			targetName := strings.TrimPrefix(hdr.Linkname, "./")
			target, targetInRootfs := strings.CutPrefix(targetName, boxRootfsPrefix)
			if targetInRootfs && boxExcluded(target) {
				// The content's first name was excluded, this one is kept.
				if promoted, ok := promotedLinks[targetName]; ok {
					// An earlier kept name already carries the content.
					hdr.Linkname = promoted
					if inRootfs {
						mf.Links = append(mf.Links, BoxManifestLink{Path: "/" + rel, Target: "/" + strings.TrimPrefix(strings.TrimPrefix(promoted, "./"), boxRootfsPrefix)})
					}
				} else {
					// This name becomes the regular file.
					body, src, ok, err := spill.open(targetName)
					if err != nil {
						return fmt.Errorf("restore %s for %s: %w", targetName, name, err)
					}
					if !ok {
						// The target was not a regular file (nothing was set
						// aside); there is no content to keep.
						log.Printf("[backup] whole-box backup of %s: hard link %s points at excluded %s, which has no content; dropped", box, name, targetName)
						continue
					}
					reg := *src
					reg.Name, reg.Linkname, reg.Typeflag = hdr.Name, "", tar.TypeReg
					entry, err := copyEntry(tw, h, &reg, body)
					if err != nil {
						return err
					}
					promotedLinks[targetName] = hdr.Name
					if inRootfs {
						entry.Path = "/" + rel
						mf.Files = append(mf.Files, entry)
					}
					continue
				}
			} else if inRootfs && targetInRootfs {
				mf.Links = append(mf.Links, BoxManifestLink{Path: "/" + rel, Target: "/" + target})
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
			return err
		}
		if inRootfs {
			entry.Path = "/" + rel
			mf.Files = append(mf.Files, entry)
		} else {
			entry.Path = name
			mf.Config = append(mf.Config, entry)
		}
	}
	// After the tar end marker only zero padding may follow, and the gzip
	// stream must end cleanly: a truncated export is a failed backup, never
	// a short one.
	trailing, err := io.CopyN(zeroOnly{}, plain, maxBoxTrailingBytes+1)
	switch {
	case errors.Is(err, errNonZeroTrailing) || trailing > maxBoxTrailingBytes:
		return fmt.Errorf("read export: trailing data after the end of the archive")
	case err != nil && !errors.Is(err, io.EOF):
		return fmt.Errorf("read export: %w", err)
	}

	body, err := json.Marshal(&mf)
	if err != nil {
		return fmt.Errorf("encode manifest: %w", err)
	}
	if err := tw.WriteHeader(&tar.Header{
		Name: BoxManifestPath, Typeflag: tar.TypeReg, Mode: 0o600, Size: int64(len(body)), ModTime: now,
	}); err != nil {
		return fmt.Errorf("write manifest: %w", err)
	}
	if _, err := tw.Write(body); err != nil {
		return fmt.Errorf("write manifest: %w", err)
	}
	if err := tw.Close(); err != nil {
		return err
	}
	return gzw.Close()
}

// copyEntry writes a regular file entry from body, digesting it.
func copyEntry(tw *tar.Writer, h hash.Hash, hdr *tar.Header, body io.Reader) (BoxManifestFile, error) {
	if err := tw.WriteHeader(hdr); err != nil {
		return BoxManifestFile{}, fmt.Errorf("write %s: %w", hdr.Name, err)
	}
	h.Reset()
	n, err := io.CopyN(io.MultiWriter(tw, h), body, hdr.Size)
	if err != nil {
		return BoxManifestFile{}, fmt.Errorf("copy %s: %w", hdr.Name, err)
	}
	return BoxManifestFile{Size: n, SHA256: hex.EncodeToString(h.Sum(nil))}, nil
}

// boxSpill keeps the content of dropped regular files, in case a kept hard
// link needs it. Each file is its own age segment, appended to one temp
// file and encrypted to an identity held only in memory, so the host holds
// ciphertext only, as for the staged archive.
type boxSpill struct {
	dir      string
	f        *os.File
	identity *age.X25519Identity
	end      int64
	entries  map[string]boxSpillEntry
}

type boxSpillEntry struct {
	off, n int64
	hdr    *tar.Header
}

func (s *boxSpill) add(name string, hdr *tar.Header, body io.Reader) error {
	if s.f == nil {
		id, err := age.GenerateX25519Identity()
		if err != nil {
			return err
		}
		f, err := os.CreateTemp(s.dir, ".box-spill-*.tmp")
		if err != nil {
			return err
		}
		s.f, s.identity, s.entries = f, id, map[string]boxSpillEntry{}
	}
	cw := &countingWriter{w: s.f}
	w, err := age.Encrypt(cw, s.identity.Recipient())
	if err != nil {
		return err
	}
	if _, err := io.Copy(w, body); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	keep := *hdr
	s.entries[name] = boxSpillEntry{off: s.end, n: cw.n, hdr: &keep}
	s.end += cw.n
	return nil
}

// open returns the set-aside content and header of name, and false when
// nothing was set aside under it.
func (s *boxSpill) open(name string) (io.Reader, *tar.Header, bool, error) {
	e, ok := s.entries[name]
	if !ok {
		return nil, nil, false, nil
	}
	r, err := age.Decrypt(io.NewSectionReader(s.f, e.off, e.n), s.identity)
	if err != nil {
		return nil, nil, false, err
	}
	return r, e.hdr, true, nil
}

func (s *boxSpill) close() {
	if s.f != nil {
		_ = s.f.Close()
		_ = os.Remove(s.f.Name())
	}
}

type countingWriter struct {
	w io.Writer
	n int64
}

func (c *countingWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}

// maxBoxTrailingBytes bounds the zero padding accepted after the tar end
// marker (a tar writer pads to its record size, 10 KiB for GNU tar).
const maxBoxTrailingBytes = 1 << 20

var errNonZeroTrailing = errors.New("non-zero trailing data")

// zeroOnly accepts zero bytes and refuses anything else.
type zeroOnly struct{}

func (zeroOnly) Write(p []byte) (int, error) {
	for i, b := range p {
		if b != 0 {
			return i, errNonZeroTrailing
		}
	}
	return len(p), nil
}

// boxExcluded reports whether a rootfs-relative path is inside one of the
// excluded directories. The directory itself ("tmp", "tmp/") is not.
func boxExcluded(rel string) bool {
	for _, d := range boxExcludedDirs {
		if rest, ok := strings.CutPrefix(rel, d+"/"); ok && rest != "" {
			return true
		}
	}
	return false
}
