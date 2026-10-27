package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"google.golang.org/protobuf/encoding/protojson"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

var (
	sshKeysServer   string
	sshKeysKeys     []string
	sshKeysKeyFiles []string
	sshKeysEmpty    bool
)

var sshKeysCmd = &cobra.Command{
	Use:   "ssh-keys",
	Short: "Manage the SSH keys authorized on a box",
}

var sshKeysSetCmd = &cobra.Command{
	Use:   "set <box>",
	Short: "Replace a box user's authorized SSH keys with exactly the given list",
	Long: `Make the box user's authorized SSH keys exactly the keys you pass.

Keys not in the list are removed and revoked; keys the platform manages
itself are always kept. Running the same command twice gives the same result.
Every key must be a single-line public key with no options (command=, from=):
one invalid key fails the whole call and changes nothing.

A key dropped here is revoked in the daemon's key registry if you registered
it, so it is also revoked for your other boxes where it remains in the file.
A key another account registered (its public key copied onto your box) is
only removed from your box; that account's registry entry stays active.

An empty list removes every key you manage and must be asked for with --empty.

Examples:
  containarium ssh-keys set my-box --key-file ~/.ssh/id_ed25519.pub --key-file ./ci.pub
  containarium ssh-keys set my-box --empty`,
	Args: cobra.ExactArgs(1),
	RunE: runSSHKeysSet,
}

func init() {
	sshKeysSetCmd.Flags().StringVar(&sshKeysServer, "server", "", "server to talk to (default: your logged-in server)")
	sshKeysSetCmd.Flags().StringArrayVar(&sshKeysKeys, "key", nil, "public key to authorize (repeatable)")
	sshKeysSetCmd.Flags().StringArrayVar(&sshKeysKeyFiles, "key-file", nil, "file holding one public key to authorize (repeatable)")
	sshKeysSetCmd.Flags().BoolVar(&sshKeysEmpty, "empty", false, "remove every key you manage (required to send an empty list)")
	sshKeysCmd.AddCommand(sshKeysSetCmd)
	rootCmd.AddCommand(sshKeysCmd)
}

// buildSetSSHKeysRequest assembles the request. Keys are passed through
// untouched: validation is the daemon's job, so the CLI cannot disagree with it.
func buildSetSSHKeysRequest(box string, keys, keyFiles []string, empty bool) (*pb.SetSSHKeysRequest, error) {
	all := append([]string{}, keys...)
	for _, f := range keyFiles {
		b, err := os.ReadFile(f) // #nosec G304 -- path from an explicit flag
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", f, err)
		}
		all = append(all, strings.TrimSpace(string(b)))
	}
	switch {
	case len(all) == 0 && !empty:
		return nil, fmt.Errorf("no keys given: pass --key/--key-file, or --empty to remove every key")
	case len(all) > 0 && empty:
		return nil, fmt.Errorf("--empty cannot be combined with --key/--key-file")
	}
	return &pb.SetSSHKeysRequest{Username: box, SshPublicKeys: all, AllowEmpty: empty}, nil
}

func (c *connectAPI) SetSSHKeys(ctx context.Context, req *pb.SetSSHKeysRequest) (*pb.SetSSHKeysResponse, error) {
	b, err := protojson.Marshal(req)
	if err != nil {
		return nil, err
	}
	var out struct {
		Message     string `json:"message"`
		RemovedKeys int32  `json:"removedKeys"`
		TotalKeys   int32  `json:"totalKeys"`
	}
	if _, err := c.do(ctx, http.MethodPut, "/v1/containers/"+url.PathEscape(req.Username)+"/ssh-keys", json.RawMessage(b), &out); err != nil {
		return nil, err
	}
	return &pb.SetSSHKeysResponse{Message: out.Message, RemovedKeys: out.RemovedKeys, TotalKeys: out.TotalKeys}, nil
}

func runSSHKeysSet(cmd *cobra.Command, args []string) error {
	box := args[0]
	if err := validateBoxName(box); err != nil {
		return err
	}
	req, err := buildSetSSHKeysRequest(box, sshKeysKeys, sshKeysKeyFiles, sshKeysEmpty)
	if err != nil {
		return err
	}
	api, err := newConnectAPI(pickSSHServer(sshKeysServer))
	if err != nil {
		return err
	}
	resp, err := api.SetSSHKeys(cmd.Context(), req)
	if err != nil {
		return err
	}
	fmt.Fprintf(cmd.OutOrStdout(), "%s (removed %d, %d caller-managed key(s) now authorized)\n", resp.Message, resp.RemovedKeys, resp.TotalKeys)
	return nil
}
