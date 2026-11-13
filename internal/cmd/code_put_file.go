package cmd

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/footprintai/containarium/internal/client"
	"github.com/footprintai/containarium/internal/coderun"
	"github.com/spf13/cobra"
)

// `containarium code put-file` (#3548) writes one local file into a box user's
// home through the daemon's WriteBoxFile: no SSH client, and the bytes never
// pass through a shell.

var codePutFileCmd = &cobra.Command{
	Use:   "put-file <box> <local-file> [<remote-path>]",
	Short: "Write a local file into a box user's home directory",
	Long: fmt.Sprintf(`Copy <local-file> to <remote-path> under the box user's home directory,
through the daemon (#3548), so a run on the box can read it. <remote-path> is
relative to the home directory (default: the file's base name) and must stay
inside it: no absolute path, no "..", and nothing under .ssh or .containarium.
Parent directories are created with mode 0700; the file is written whole or
not at all, owned by the box user with mode 0600, and replaces an existing file.

With --for-run, on a box with a recorded tool-access level, the file goes into
the unprivileged run user's home instead, owned by the run user: platform runs
execute as that user, so only then can a run read the file (a daemon with the
box_files_run_user capability). Without it the file stays in the owner's home,
where an SSH session reads it. The path printed is where the file is.

The file's SHA-256 is sent and checked against the bytes that land on the box.
A file above %d bytes is streamed (WriteBoxFileStream, a daemon with the
box_files_stream capability), up to %d bytes per file.

Examples:
  containarium code put-file alice ./brief.md attachments/turn-1/brief.md --server <host>
  containarium code put-file alice ./data.csv --server <host>`, coderun.MaxBoxFileBytes, coderun.MaxBoxFileStreamBytes),
	Args: cobra.RangeArgs(2, 3),
	RunE: runCodePutFile,
}

var codePutFileForRun bool

func init() {
	codeCmd.AddCommand(codePutFileCmd)
	codePutFileCmd.Flags().BoolVar(&codePutFileForRun, "for-run", false,
		"Place the file for a platform run: in the run user's home on a box with a recorded tool-access level")
}

// boxFileWriter is what the command needs from a daemon client: the unary
// write, and the stream for a file above its cap.
type boxFileWriter interface {
	client.BoxFileWriter
	client.BoxFileStreamWriter
}

func runCodePutFile(cmd *cobra.Command, args []string) error {
	if err := client.ValidateBoxName(args[0]); err != nil {
		return err
	}
	if serverAddr == "" {
		return fmt.Errorf("--server is required")
	}
	var c interface {
		boxFileWriter
		Close() error
	}
	var err error
	if httpMode {
		c, err = client.NewHTTPClient(serverAddr, authToken)
	} else {
		c, err = client.NewGRPCClient(serverAddr, certsDir, insecure)
	}
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()
	remote := ""
	if len(args) == 3 {
		remote = args[2]
	}
	return codePutFile(c, args[0], args[1], remote, codePutFileForRun, os.Stdout)
}

func codePutFile(c boxFileWriter, box, local, remote string, forRun bool, w io.Writer) error {
	st, err := os.Stat(local)
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", local)
	}
	if st.Size() > coderun.MaxBoxFileStreamBytes {
		return fmt.Errorf("%s is %d bytes; the limit is %d", local, st.Size(), coderun.MaxBoxFileStreamBytes)
	}
	if remote == "" {
		remote = filepath.Base(local)
	}
	if st.Size() > coderun.MaxBoxFileBytes {
		return codePutFileStream(c, box, local, remote, forRun, w)
	}
	content, err := os.ReadFile(local)
	if err != nil {
		return err
	}
	// client.PutBoxFile is the function the MCP tool put_file calls too.
	resp, err := client.PutBoxFile(c, client.BoxFileParams{Box: box, Path: remote, Content: content, ForRun: forRun})
	if isUnimplemented(err) {
		return fmt.Errorf("%s", client.BoxFilesUnsupportedMessage)
	}
	if err != nil {
		return err
	}
	_, err = io.WriteString(w, client.RenderBoxFileWrite(box, resp))
	return err
}

// codePutFileStream sends a file above the unary cap through
// WriteBoxFileStream (#3548): one pass to hash it, a second to stream it. The
// size and checksum are those of the bytes hashed, so a file that changes in
// between fails the daemon's check and leaves nothing on the box.
func codePutFileStream(c boxFileWriter, box, local, remote string, forRun bool, w io.Writer) error {
	f, err := os.Open(local) // #nosec G304 -- the operator named this file
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return fmt.Errorf("read %s: %w", local, err)
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return err
	}
	resp, err := client.PutBoxFileStream(c, client.BoxFileStreamParams{
		Box: box, Path: remote, Content: io.LimitReader(f, n), Size: n, SHA256: hex.EncodeToString(h.Sum(nil)), ForRun: forRun,
	})
	if isUnimplemented(err) {
		return errors.New(client.BoxFilesStreamUnsupportedMessage)
	}
	if err != nil {
		return err
	}
	_, err = io.WriteString(w, client.RenderBoxFileWrite(box, resp))
	return err
}
