package sdlcskills

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"regexp"
	"strings"
)

// Bundle is a verified, in-memory view of sdlc-skills.tar.gz, the release
// asset scripts/build-sdlc-skills-bundle.sh produces and the boxes install.
// A daemon that composes a hosted skill's prompt from it (#2488) therefore
// runs the same pinned bytes the boxes do.
type Bundle struct {
	pin   string
	files map[string]string
}

// Pin names the content, e.g. "FootprintAI/open-sdlc-skills@<sha12>", for
// stamping into whatever is derived from it.
func (b *Bundle) Pin() string { return b.pin }

// Section returns one bold section of one skill's body (see ExtractSection),
// or false if the skill or the section is absent. This is what a hosted skill
// composes its prompt from.
func (b *Bundle) Section(skill, heading string) (string, bool) {
	body, ok := b.SkillBody(skill)
	if !ok {
		return "", false
	}
	return ExtractSection(body, heading)
}

// maxBundleBytes bounds what LoadBundle will read: the real asset is ~100 KB
// of markdown, so a multi-megabyte file at that path is not it.
const maxBundleBytes = 8 << 20

// LoadBundle reads the tarball at path and verifies it against the pin this
// binary was built with. Anything but the exact pinned bytes is an error; the
// caller falls back to its inline prompt rather than trusting other content.
func LoadBundle(filePath string) (*Bundle, error) {
	lock, err := Embedded()
	if err != nil {
		return nil, err
	}
	f, err := os.Open(filePath) // #nosec G304 -- operator-configured bundle path, verified by digest below
	if err != nil {
		return nil, fmt.Errorf("sdlcskills: open bundle: %w", err)
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, maxBundleBytes+1))
	if err != nil {
		return nil, fmt.Errorf("sdlcskills: read bundle: %w", err)
	}
	if len(data) > maxBundleBytes {
		return nil, fmt.Errorf("sdlcskills: bundle at %s exceeds %d bytes; not the pinned asset", filePath, maxBundleBytes)
	}
	return LoadBundleBytes(data, lock)
}

// LoadBundleBytes verifies data against lock and parses it. Exposed so a
// caller with its own lock (tests, tooling) can use the same verification.
func LoadBundleBytes(data []byte, lock Lock) (*Bundle, error) {
	sum := sha256.Sum256(data)
	if got := hex.EncodeToString(sum[:]); got != lock.SHA256 {
		return nil, fmt.Errorf("sdlcskills: bundle digest %s does not match the pinned digest %s", got[:12], lock.SHA256[:12])
	}
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("sdlcskills: bundle is not gzip: %w", err)
	}
	defer func() { _ = gz.Close() }()

	files := map[string]string{}
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("sdlcskills: read bundle entry: %w", err)
		}
		name := h.Name
		// Nothing in the pinned set is absolute or walks up; refuse the whole
		// bundle if anything does, the same posture as the installer.
		if strings.HasPrefix(name, "/") || name != path.Clean(name) || strings.HasPrefix(name, "..") || strings.Contains(name, "/../") {
			return nil, fmt.Errorf("sdlcskills: unsafe path in bundle: %q", name)
		}
		if h.Typeflag != tar.TypeReg {
			continue
		}
		body, err := io.ReadAll(io.LimitReader(tr, maxBundleBytes))
		if err != nil {
			return nil, fmt.Errorf("sdlcskills: read %s: %w", name, err)
		}
		files[name] = string(body)
	}
	ref := lock.Ref
	if len(ref) > 12 {
		ref = ref[:12]
	}
	return &Bundle{pin: lock.Repo + "@" + ref, files: files}, nil
}

// SkillBody returns the markdown body of <skill>/SKILL.md with its YAML
// frontmatter removed, or false if the bundle has no such skill.
func (b *Bundle) SkillBody(skill string) (string, bool) {
	raw, ok := b.files[skill+"/SKILL.md"]
	if !ok {
		return "", false
	}
	return StripFrontmatter(raw), true
}

// StripFrontmatter removes a leading `---` ... `---` YAML block, if any.
func StripFrontmatter(md string) string {
	if !strings.HasPrefix(md, "---\n") {
		return strings.TrimLeft(md, "\n")
	}
	rest := md[len("---\n"):]
	end := strings.Index(rest, "\n---\n")
	if end < 0 {
		return strings.TrimLeft(md, "\n")
	}
	return strings.TrimLeft(rest[end+len("\n---\n"):], "\n")
}

// boldHeading matches a line that is only a bold phrase, which is how the
// open-sdlc-skills files mark their sections ("**Engineering principles**").
var boldHeading = regexp.MustCompile(`^\*\*[^*]+\*\*\s*$`)

// ExtractSection returns the text under the bold heading `**<heading>**`, up
// to the next bold or `#` heading, without the heading line itself. It is
// deliberately one section: the rest of a role skill describes an interactive
// workflow a hosted run cannot perform, and feeding that to a model with an
// instruction to ignore it degrades the output.
func ExtractSection(body, heading string) (string, bool) {
	want := "**" + heading + "**"
	lines := strings.Split(body, "\n")
	start := -1
	for i, l := range lines {
		if strings.TrimSpace(l) == want {
			start = i + 1
			break
		}
	}
	if start < 0 {
		return "", false
	}
	end := len(lines)
	for i := start; i < len(lines); i++ {
		t := strings.TrimSpace(lines[i])
		if boldHeading.MatchString(t) || strings.HasPrefix(t, "#") {
			end = i
			break
		}
	}
	return strings.TrimSpace(strings.Join(lines[start:end], "\n")), true
}
