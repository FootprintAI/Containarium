package cmd

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/footprintai/containarium/internal/client"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// `containarium notify` (#2185) sets where the daemon pushes a `code run
// --approvals ask` permission request that is waiting on you. The daemon
// sends the push itself, so it reaches you with the laptop closed; the
// channel's token is stored as a broker-only secret and never reaches a box.

var notifyCmd = &cobra.Command{
	Use:   "notify",
	Short: "Get a push notification when a code run waits on your approval",
	Long: `Configure the push channel the daemon uses when a ` + "`code run --approvals ask`" + `
run is waiting on a permission request. Only ntfy is supported.

The push carries the box, the run, the tool, for Bash its command (at most
200 characters), and when the request expires. It never carries file
contents, environment values or any other tool input; --redact-command
drops the command too.

ntfy.sh topics are public: anyone who knows or guesses a topic name can read
its messages. Use an access-controlled topic with a token, or a self-hosted
ntfy server. See docs/NOTIFY-NTFY.md.

Requires --server (the daemon holds the channel).`,
}

var (
	notifyUser          string
	notifyNtfyServer    string
	notifyNtfyTopic     string
	notifyTokenFile     string
	notifyTokenStdin    bool
	notifyClearToken    bool
	notifyRedactCommand bool
)

var notifySetCmd = &cobra.Command{
	Use:   "set",
	Short: "Set your notification channel",
}

var notifySetNtfyCmd = &cobra.Command{
	Use:   "ntfy --ntfy-server <url> --topic <topic> [--token-file <path> | --token-stdin]",
	Short: "Push waiting permission requests to an ntfy topic",
	Long: `Push waiting permission requests to an ntfy topic.

--ntfy-server is the ntfy server's base URL (https://ntfy.sh or your own).
It is not named --server: that is the global flag naming the daemon, which
stores the channel and sends the pushes.

  containarium --server <daemon> notify set ntfy --ntfy-server https://ntfy.example.com --topic my-runs --token-file ~/.ntfy-token

The access token is read from --token-file or from stdin (--token-stdin),
never from a flag, so it does not land in shell history. With a token the
server must be https. Running set again without a token keeps the stored one;
--clear-token removes it.`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		token, err := readNotifyToken(cmd.InOrStdin(), notifyTokenFile, notifyTokenStdin)
		if err != nil {
			return err
		}
		if token != "" && notifyClearToken {
			return errors.New("--clear-token cannot be combined with --token-file or --token-stdin")
		}
		return runNotifySet(cmd.OutOrStdout(), &pb.SetNotifyChannelRequest{
			Username:      notifyUser,
			Kind:          pb.NotifyChannelKind_NOTIFY_CHANNEL_KIND_NTFY,
			Server:        notifyNtfyServer,
			Topic:         notifyNtfyTopic,
			Token:         token,
			ClearToken:    notifyClearToken,
			RedactCommand: notifyRedactCommand,
		})
	},
}

var notifyShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Show your notification channel (never the token)",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		return runNotifyShow(cmd.OutOrStdout(), notifyUser)
	},
}

var notifyDeleteCmd = &cobra.Command{
	Use:     "delete",
	Aliases: []string{"rm"},
	Short:   "Remove your notification channel and its stored token",
	Args:    cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		return runNotifyDelete(cmd.OutOrStdout(), notifyUser)
	},
}

var notifyTestCmd = &cobra.Command{
	Use:   "test",
	Short: "Send one test push through your notification channel",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		return runNotifyTest(cmd.OutOrStdout(), notifyUser)
	},
}

func init() {
	rootCmd.AddCommand(notifyCmd)
	notifyCmd.AddCommand(notifySetCmd, notifyShowCmd, notifyDeleteCmd, notifyTestCmd)
	notifySetCmd.AddCommand(notifySetNtfyCmd)
	notifyCmd.PersistentFlags().StringVar(&notifyUser, "user", "", "whose channel (default: you; another user needs admin)")

	f := notifySetNtfyCmd.Flags()
	f.StringVar(&notifyNtfyServer, "ntfy-server", "", "ntfy server base URL, e.g. https://ntfy.example.com (required)")
	f.StringVar(&notifyNtfyTopic, "topic", "", "ntfy topic (required)")
	f.StringVar(&notifyTokenFile, "token-file", "", "file holding the topic's access token")
	f.BoolVar(&notifyTokenStdin, "token-stdin", false, "read the topic's access token from stdin")
	f.BoolVar(&notifyClearToken, "clear-token", false, "remove the stored access token")
	f.BoolVar(&notifyRedactCommand, "redact-command", false, "send the tool name only, never its command")
	_ = notifySetNtfyCmd.MarkFlagRequired("ntfy-server")
	_ = notifySetNtfyCmd.MarkFlagRequired("topic")
	notifySetNtfyCmd.MarkFlagsMutuallyExclusive("token-file", "token-stdin")
}

// readNotifyToken reads the token from a file or stdin. Only the first line
// counts, trimmed; an empty one is an error, not "no token".
func readNotifyToken(stdin io.Reader, file string, fromStdin bool) (string, error) {
	var (
		r     io.Reader
		where string
	)
	switch {
	case file != "":
		f, err := os.Open(file) // #nosec G304 -- the user's own token file
		if err != nil {
			return "", fmt.Errorf("read --token-file: %w", err)
		}
		defer func() { _ = f.Close() }()
		r, where = f, "--token-file "+file
	case fromStdin:
		r, where = stdin, "stdin"
	default:
		return "", nil
	}
	line, err := bufio.NewReader(io.LimitReader(r, 64<<10)).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", fmt.Errorf("read token from %s: %w", where, err)
	}
	token := strings.TrimSpace(line)
	if token == "" {
		return "", fmt.Errorf("no token in %s", where)
	}
	return token, nil
}

// newNotifyClient dials the daemon over the transport the global flags
// selected. A variable so tests can substitute a fake.
var newNotifyClient = func() (client.NotifyAPI, error) {
	if serverAddr == "" {
		return nil, errors.New("--server is required for notify (the daemon holds the channel and sends the pushes)")
	}
	if httpMode {
		return client.NewHTTPClient(serverAddr, authToken)
	}
	return client.NewGRPCClient(serverAddr, certsDir, insecure)
}

func writeNotifyChannel(w io.Writer, ch *pb.NotifyChannel) error {
	// What `show` says about the token; never the token itself.
	stored := "none"
	if ch.GetHasToken() {
		stored = "stored (broker-only secret)"
	}
	cmdLine := "shown (Bash only, ≤ 200 chars)"
	if ch.GetRedactCommand() {
		cmdLine = "redacted (tool name only)"
	}
	_, err := fmt.Fprintf(w, "user:     %s\nchannel:  ntfy\nserver:   %s\ntopic:    %s\ntoken:    %s\ncommand:  %s\n",
		ch.GetUsername(), ch.GetServer(), ch.GetTopic(), stored, cmdLine)
	return err
}

func runNotifySet(w io.Writer, req *pb.SetNotifyChannelRequest) error {
	c, err := newNotifyClient()
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()
	resp, err := c.SetNotifyChannel(req)
	if err != nil {
		return fmt.Errorf("set notification channel: %w", err)
	}
	if _, err := fmt.Fprintln(w, "✓ notification channel stored; check it with `containarium notify test`"); err != nil {
		return err
	}
	return writeNotifyChannel(w, resp.GetChannel())
}

func runNotifyShow(w io.Writer, user string) error {
	c, err := newNotifyClient()
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()
	resp, err := c.GetNotifyChannel(&pb.GetNotifyChannelRequest{Username: user})
	if err != nil {
		return fmt.Errorf("get notification channel: %w", err)
	}
	return writeNotifyChannel(w, resp.GetChannel())
}

func runNotifyDelete(w io.Writer, user string) error {
	c, err := newNotifyClient()
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()
	if _, err := c.DeleteNotifyChannel(&pb.DeleteNotifyChannelRequest{Username: user}); err != nil {
		return fmt.Errorf("delete notification channel: %w", err)
	}
	_, err = fmt.Fprintln(w, "✓ notification channel removed")
	return err
}

func runNotifyTest(w io.Writer, user string) error {
	c, err := newNotifyClient()
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()
	resp, err := c.TestNotifyChannel(&pb.TestNotifyChannelRequest{Username: user})
	if err != nil {
		return fmt.Errorf("send test notification: %w", err)
	}
	_, err = fmt.Fprintln(w, "✓ "+resp.GetMessage())
	return err
}
