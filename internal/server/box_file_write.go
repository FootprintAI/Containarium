package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"path"
	"regexp"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/internal/coderun"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// WriteBoxFile (#3548): put one file in a box user's home so a run can read it,
// with no SSH client and no bytes embedded in a `command` run.
//
// The bytes travel through the container file API, never through a shell, so
// content can never be read as a command. That API writes as root, though, and
// follows symlinks in the path, so it is never aimed at a path the box user
// influences: the file lands in an unguessable root-made staging name, is
// handed to the box user, and the box user's own script moves it into place.
// Whatever the user's directory layout is, the final write can reach only what
// the user could already write. The rename makes the file appear whole or not
// at all, and the checksum is taken over the bytes on the box, before the rename.

const (
	// MaxBoxFileBytes is the largest file WriteBoxFile accepts. Under gRPC's
	// default 4 MiB message cap with room for the JSON/base64 gateway framing.
	MaxBoxFileBytes = coderun.MaxBoxFileBytes
	// DaemonCapBoxFiles: the WriteBoxFile RPC (#3548).
	DaemonCapBoxFiles = "box_files"

	maxBoxFilePathBytes = 1024
	// Leaves room for the ".cbf.<pid>" suffix of the temp file (NAME_MAX is 255).
	maxBoxFileSegmentBytes = 200
	boxFileDefaultMode     = "0600"
	boxFileStageDefaultDir = "/tmp"
	// Printed on the script's stderr so the daemon can tell a refusal from a failure.
	boxFileMarkerDir = "CBF_ERR_DIR"
	boxFileMarkerSHA = "CBF_ERR_SHA"
)

var boxFileSHA256Pattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// boxFileWriteFunc is the file API seam: write content at path inside the box.
type boxFileWriteFunc func(box, path string, content []byte, mode string) error

func (s *ContainerServer) boxFileWriteFn() boxFileWriteFunc {
	if s.boxFileWrite != nil {
		return s.boxFileWrite
	}
	if s.manager == nil {
		return nil
	}
	return s.manager.WriteFile
}

// cleanBoxFilePath validates a path relative to the box user's home. It
// demands the canonical spelling rather than cleaning it, so what the caller
// asked for is what is written.
func cleanBoxFilePath(p string) (string, error) {
	switch {
	case p == "":
		return "", fmt.Errorf("path is required")
	case len(p) > maxBoxFilePathBytes:
		return "", fmt.Errorf("path must be at most %d bytes", maxBoxFilePathBytes)
	case strings.HasPrefix(p, "/"):
		return "", fmt.Errorf("path must be relative to the box user's home directory")
	}
	for _, r := range p {
		if r < 0x20 || r == 0x7f {
			return "", fmt.Errorf("path must not contain control characters")
		}
	}
	if path.Clean(p) != p || p == "." {
		return "", fmt.Errorf("path must be a clean relative path inside the home directory (no \"..\", \".\", empty or trailing segments)")
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == ".." || len(seg) > maxBoxFileSegmentBytes {
			return "", fmt.Errorf("path must stay inside the home directory and keep each segment under %d bytes", maxBoxFileSegmentBytes)
		}
	}
	if first := strings.SplitN(p, "/", 2)[0]; first == ".ssh" || first == ".containarium" {
		return "", fmt.Errorf("path must not be under %s: the platform manages it", first)
	}
	return p, nil
}

// WriteBoxFile implements pb.ContainerServiceServer.
func (s *ContainerServer) WriteBoxFile(ctx context.Context, req *pb.WriteBoxFileRequest) (*pb.WriteBoxFileResponse, error) {
	if err := validateBoxRunOwner(req.GetUsername()); err != nil {
		return nil, err
	}
	rel, err := cleanBoxFilePath(req.GetPath())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	if len(req.GetContent()) > MaxBoxFileBytes {
		return nil, status.Errorf(codes.InvalidArgument, "content is %d bytes; the limit is %d", len(req.GetContent()), MaxBoxFileBytes)
	}
	mode := req.GetMode()
	if mode == "" {
		mode = boxFileDefaultMode
	}
	if mode != "0600" && mode != "0400" {
		return nil, status.Error(codes.InvalidArgument, `mode must be "0600" or "0400"`)
	}
	want := req.GetSha256()
	if want != "" && !boxFileSHA256Pattern.MatchString(want) {
		return nil, status.Error(codes.InvalidArgument, "sha256 must be 64 lowercase hex characters")
	}
	if err := s.authorizeBoxRuns(ctx, req.GetUsername()); err != nil {
		return nil, err
	}

	rootExec, userExec, write := s.boxRunExecFn(), s.boxRunStartExecFn(), s.boxFileWriteFn()
	if rootExec == nil || userExec == nil || write == nil {
		return nil, status.Error(codes.Unavailable, "no container backend to write a file on")
	}
	box := req.GetUsername() + "-container"
	home, err := resolveBoxRunHome(userExec, box, req.GetUsername())
	if err != nil {
		return nil, err
	}
	home = strings.TrimSpace(home)
	if !path.IsAbs(home) || path.Clean(home) != home || strings.ContainsAny(home, "\n\x00") {
		return nil, status.Errorf(codes.FailedPrecondition, "the box user's home directory %q is not a plain absolute path", home)
	}
	dst := path.Join(home, rel)

	stage, err := s.newBoxFileStagePath()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "stage name: %v", err)
	}
	removeStage := func() { _, _ = rootExec(box, "rm -f -- "+shellSingleQuote(stage)) }
	if err := write(box, stage, req.GetContent(), "0600"); err != nil {
		removeStage()
		return nil, status.Errorf(codes.Unavailable, "write %s: %v", req.GetPath(), err)
	}
	if _, err := rootExec(box, "chown -- "+shellSingleQuote(req.GetUsername())+" "+shellSingleQuote(stage)); err != nil {
		removeStage()
		return nil, status.Errorf(codes.Unavailable, "hand the staged file to %s: %v", req.GetUsername(), err)
	}
	out, err := userExec(box, req.GetUsername(), boxFilePlaceScript(dst, stage, want, mode))
	if err != nil {
		removeStage()
		switch {
		case strings.Contains(err.Error(), boxFileMarkerSHA):
			return nil, status.Errorf(codes.DataLoss, "the bytes on the box do not match sha256 %s; no file was written", want)
		case strings.Contains(err.Error(), boxFileMarkerDir):
			return nil, status.Errorf(codes.FailedPrecondition, "%s is a directory", req.GetPath())
		}
		return nil, status.Errorf(codes.FailedPrecondition, "place %s: %v", req.GetPath(), err)
	}
	got := strings.TrimSpace(out)
	if !boxFileSHA256Pattern.MatchString(got) {
		return nil, status.Errorf(codes.Internal, "the box reported no checksum for %s", req.GetPath())
	}
	return &pb.WriteBoxFileResponse{Path: dst, Size: int64(len(req.GetContent())), Sha256: got}, nil
}

func (s *ContainerServer) newBoxFileStagePath() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	dir := s.boxFileStageDir
	if dir == "" {
		dir = boxFileStageDefaultDir
	}
	return path.Join(dir, ".cbf-"+hex.EncodeToString(b[:])), nil
}

// boxFilePlaceScript runs as the box user: move the staged bytes to dst. umask
// 077 makes new parent directories 0700. The temp file sits beside dst so the
// final rename is atomic; the trap removes it and the staged file on any exit.
func boxFilePlaceScript(dst, stage, want, mode string) string {
	return fmt.Sprintf(`set -eu
umask 077
dst=%s
stage=%s
want=%s
tmp="$dst.cbf.$$"
trap 'rm -f -- "$stage" "$tmp"' EXIT
if [ -d "$dst" ]; then echo %s >&2; exit 3; fi
mkdir -p -- "$(dirname -- "$dst")"
cat -- "$stage" > "$tmp"
got=$(sha256sum -- "$tmp" | cut -d' ' -f1)
if [ -n "$want" ] && [ "$got" != "$want" ]; then echo %s >&2; exit 4; fi
chmod %s -- "$tmp"
mv -fT -- "$tmp" "$dst"
printf '%%s\n' "$got"
`, shellSingleQuote(dst), shellSingleQuote(stage), shellSingleQuote(want), boxFileMarkerDir, boxFileMarkerSHA, mode)
}
