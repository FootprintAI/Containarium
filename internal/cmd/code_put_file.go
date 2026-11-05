package cmd

import (
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

The file's SHA-256 is sent and checked against the bytes that land on the box.
At most %d bytes per file.

Examples:
  containarium code put-file alice ./brief.md attachments/turn-1/brief.md --server <host>
  containarium code put-file alice ./data.csv --server <host>`, coderun.MaxBoxFileBytes),
	Args: cobra.RangeArgs(2, 3),
	RunE: runCodePutFile,
}

func init() {
	codeCmd.AddCommand(codePutFileCmd)
}

// boxFileWriter is what the command needs from a daemon client.
type boxFileWriter = client.BoxFileWriter

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
	return codePutFile(c, args[0], args[1], remote, os.Stdout)
}

func codePutFile(c boxFileWriter, box, local, remote string, w io.Writer) error {
	st, err := os.Stat(local)
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", local)
	}
	if st.Size() > coderun.MaxBoxFileBytes {
		return fmt.Errorf("%s is %d bytes; the limit is %d", local, st.Size(), coderun.MaxBoxFileBytes)
	}
	content, err := os.ReadFile(local)
	if err != nil {
		return err
	}
	if remote == "" {
		remote = filepath.Base(local)
	}
	// client.PutBoxFile is the function the MCP tool put_file calls too.
	resp, err := client.PutBoxFile(c, client.BoxFileParams{Box: box, Path: remote, Content: content})
	if isUnimplemented(err) {
		return fmt.Errorf("%s", client.BoxFilesUnsupportedMessage)
	}
	if err != nil {
		return err
	}
	_, err = io.WriteString(w, client.RenderBoxFileWrite(box, resp))
	return err
}
