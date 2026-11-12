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
func cleanBoxFilePath(p string) (string, error) { return coderun.CleanHomeRelPath("path", p) }

// WriteBoxFile implements pb.ContainerServiceServer.
func (s *ContainerServer) WriteBoxFile(ctx context.Context, req *pb.WriteBoxFileRequest) (*pb.WriteBoxFileResponse, error) {
	f, err := validateBoxFileTarget(req.GetUsername(), req.GetPath(), req.GetMode(), req.GetSha256())
	if err != nil {
		return nil, err
	}
	if len(req.GetContent()) > MaxBoxFileBytes {
		return nil, status.Errorf(codes.InvalidArgument, "content is %d bytes; the limit is %d", len(req.GetContent()), MaxBoxFileBytes)
	}
	if err := s.authorizeBoxRuns(ctx, req.GetUsername()); err != nil {
		return nil, err
	}
	write := s.boxFileWriteFn()
	if write == nil {
		return nil, status.Error(codes.Unavailable, "no container backend to write a file on")
	}
	got, err := s.placeBoxFile(f, func(box, stage string) error {
		if err := write(box, stage, req.GetContent(), "0600"); err != nil {
			return status.Errorf(codes.Unavailable, "write %s: %v", req.GetPath(), err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &pb.WriteBoxFileResponse{Path: f.dst, Size: int64(len(req.GetContent())), Sha256: got}, nil
}

// boxFileTarget is a validated write request: who, where, how. dst is set by
// placeBoxFile once the home directory is known.
type boxFileTarget struct {
	username, rel, mode, want string
	dst                       string
}

// validateBoxFileTarget checks what WriteBoxFile and WriteBoxFileStream share,
// before the box is touched: the owner, the path, the mode and the checksum.
func validateBoxFileTarget(username, p, mode, want string) (*boxFileTarget, error) {
	if err := validateBoxRunOwner(username); err != nil {
		return nil, err
	}
	rel, err := cleanBoxFilePath(p)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	if mode == "" {
		mode = boxFileDefaultMode
	}
	if mode != "0600" && mode != "0400" {
		return nil, status.Error(codes.InvalidArgument, `mode must be "0600" or "0400"`)
	}
	if want != "" && !boxFileSHA256Pattern.MatchString(want) {
		return nil, status.Error(codes.InvalidArgument, "sha256 must be 64 lowercase hex characters")
	}
	return &boxFileTarget{username: username, rel: rel, mode: mode, want: want}, nil
}

// placeBoxFile resolves the home, has writeStage fill a root-made staging file
// with an unguessable name, hands it to the box user and runs the box user's
// placement script; it returns the checksum of the bytes on the box. Every
// failure removes the staging file, so nothing is left at or beside f.dst.
// writeStage returns a status error.
func (s *ContainerServer) placeBoxFile(f *boxFileTarget, writeStage func(box, stage string) error) (string, error) {
	rootExec, userExec := s.boxRunExecFn(), s.boxRunStartExecFn()
	if rootExec == nil || userExec == nil {
		return "", status.Error(codes.Unavailable, "no container backend to write a file on")
	}
	box := f.username + "-container"
	home, err := resolveBoxRunHome(userExec, box, f.username)
	if err != nil {
		return "", err
	}
	home = strings.TrimSpace(home)
	if !path.IsAbs(home) || path.Clean(home) != home || strings.ContainsAny(home, "\n\x00") {
		return "", status.Errorf(codes.FailedPrecondition, "the box user's home directory %q is not a plain absolute path", home)
	}
	f.dst = path.Join(home, f.rel)

	stage, err := s.newBoxFileStagePath()
	if err != nil {
		return "", status.Errorf(codes.Internal, "stage name: %v", err)
	}
	removeStage := func() { _, _ = rootExec(box, "rm -f -- "+shellSingleQuote(stage)) }
	if err := writeStage(box, stage); err != nil {
		removeStage()
		return "", err
	}
	if _, err := rootExec(box, "chown -- "+shellSingleQuote(f.username)+" "+shellSingleQuote(stage)); err != nil {
		removeStage()
		return "", status.Errorf(codes.Unavailable, "hand the staged file to %s: %v", f.username, err)
	}
	out, err := userExec(box, f.username, boxFilePlaceScript(f.dst, stage, f.want, f.mode))
	if err != nil {
		removeStage()
		switch {
		case strings.Contains(err.Error(), boxFileMarkerSHA):
			return "", status.Errorf(codes.DataLoss, "the bytes on the box do not match sha256 %s; no file was written", f.want)
		case strings.Contains(err.Error(), boxFileMarkerDir):
			return "", status.Errorf(codes.FailedPrecondition, "%s is a directory", f.rel)
		}
		return "", status.Errorf(codes.FailedPrecondition, "place %s: %v", f.rel, err)
	}
	got := strings.TrimSpace(out)
	if !boxFileSHA256Pattern.MatchString(got) {
		return "", status.Errorf(codes.Internal, "the box reported no checksum for %s", f.rel)
	}
	return got, nil
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
