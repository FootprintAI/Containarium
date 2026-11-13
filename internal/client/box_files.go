package client

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/footprintai/containarium/internal/coderun"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// The shared half of writing a file into a box (#3548): `containarium code
// put-file` and the platform MCP tool put_file both call PutBoxFile and print
// with RenderBoxFileWrite, so a write is validated, refused and reported the
// same way on either surface. The daemon owns the path rules (relative,
// canonical, nothing under .ssh or .containarium) and the checksum check; this
// side refuses only what it can tell without the box.

// BoxFileWriter is what PutBoxFile needs from a daemon client; both GRPCClient
// and HTTPClient satisfy it.
type BoxFileWriter interface {
	WriteBoxFile(req *pb.WriteBoxFileRequest) (*pb.WriteBoxFileResponse, error)
}

// BoxFileParams is one file to write. SHA256 empty means "the checksum of
// Content", so the daemon always checks the bytes that land on the box.
type BoxFileParams struct {
	Box     string
	Path    string
	Content []byte
	Mode    string // "" (0600), "0600" or "0400"
	SHA256  string // lowercase hex; optional
	ForRun  bool   // an input for a platform run: the run user's home on a box with a tool-access level (#3678)
}

// BoxFilesUnsupportedMessage is what both surfaces say to a daemon without
// WriteBoxFile.
const BoxFilesUnsupportedMessage = "this daemon does not support writing files into a box (WriteBoxFile); upgrade it"

// BoxFileRefusedError is a refusal of WriteBoxFile: the status code the daemon
// gave next to its message, so a caller switches on Code, not on message text.
// INVALID_ARGUMENT is a path, mode or size the daemon will not take,
// DATA_LOSS a checksum mismatch (no file was written), FAILED_PRECONDITION a
// directory at the path or a box that cannot take the file.
type BoxFileRefusedError struct {
	Box     string
	Path    string
	Code    codes.Code
	Message string
}

// ReasonName is the code in its canonical spelling, e.g. "DATA_LOSS".
func (e *BoxFileRefusedError) ReasonName() string {
	return boxFileCodeNames[e.Code]
}

func (e *BoxFileRefusedError) Error() string {
	return fmt.Sprintf("put %s on %s: refused (%s): %s", e.Path, e.Box, e.ReasonName(), e.Message)
}

// boxFileCodeNames are the codes that are refusals rather than failures.
var boxFileCodeNames = map[codes.Code]string{
	codes.InvalidArgument:    "INVALID_ARGUMENT",
	codes.DataLoss:           "DATA_LOSS",
	codes.FailedPrecondition: "FAILED_PRECONDITION",
	codes.PermissionDenied:   "PERMISSION_DENIED",
	codes.NotFound:           "NOT_FOUND",
	codes.ResourceExhausted:  "RESOURCE_EXHAUSTED",
}

var boxFileSHA256Pattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// PutBoxFile writes p through c. An Unimplemented status (a daemon without the
// RPC) is returned as is, so the caller can say BoxFilesUnsupportedMessage; a
// refusal comes back as *BoxFileRefusedError.
func PutBoxFile(c BoxFileWriter, p BoxFileParams) (*pb.WriteBoxFileResponse, error) {
	if err := validateBoxFileParams(p.Box, p.Path, p.Mode, p.SHA256); err != nil {
		return nil, err
	}
	if len(p.Content) > coderun.MaxBoxFileBytes {
		return nil, fmt.Errorf("content is %d bytes; the limit is %d", len(p.Content), coderun.MaxBoxFileBytes)
	}
	want := p.SHA256
	if want == "" {
		sum := sha256.Sum256(p.Content)
		want = hex.EncodeToString(sum[:])
	}
	resp, err := c.WriteBoxFile(&pb.WriteBoxFileRequest{
		Username: p.Box, Path: p.Path, Content: p.Content, Mode: p.Mode, Sha256: want, ForRun: p.ForRun,
	})
	if err != nil {
		return nil, boxFileError(p.Box, p.Path, err)
	}
	return resp, nil
}

// boxFileError sorts a failed write: Unimplemented as is, a refusal typed,
// anything else wrapped.
func boxFileError(box, path string, err error) error {
	st, ok := status.FromError(err)
	switch {
	case ok && st.Code() == codes.Unimplemented:
		return err
	case ok && boxFileCodeNames[st.Code()] != "":
		return &BoxFileRefusedError{Box: box, Path: path, Code: st.Code(), Message: st.Message()}
	}
	return fmt.Errorf("put %s on %s: %w", path, box, err)
}

// validateBoxFileParams checks what both forms refuse before any request.
func validateBoxFileParams(box, path, mode, sha string) error {
	if err := ValidateBoxName(box); err != nil {
		return err
	}
	switch {
	case path == "":
		return fmt.Errorf("a remote path is required")
	case mode != "" && mode != "0600" && mode != "0400":
		return fmt.Errorf(`mode must be "0600" or "0400", got %q`, mode)
	case sha != "" && !boxFileSHA256Pattern.MatchString(sha):
		return fmt.Errorf("sha256 must be 64 lowercase hex characters")
	}
	return nil
}

// RenderBoxFileWrite is the one-line report of a write.
func RenderBoxFileWrite(box string, resp *pb.WriteBoxFileResponse) string {
	return fmt.Sprintf("%s: wrote %s (%d bytes, sha256 %s)\n", box, resp.GetPath(), resp.GetSize(), resp.GetSha256())
}
