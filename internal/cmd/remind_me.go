package cmd

import (
	"errors"
	"fmt"
	"net/mail"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

// remindMeFile is the opt-in file the daemon pre-creates in every
// anonymous box (internal/anonbox.RemindFilePath); a var so tests can
// point it at a temp file.
var remindMeFile = "/etc/containarium/remind-me"

var remindMeClear bool

var remindMeCmd = &cobra.Command{
	Use:   "remind-me <email>",
	Short: "Get one email before this anonymous box expires (opt-in)",
	Long: `Run INSIDE an anonymous box (one you reached with ssh new.<domain>).

About 30 minutes before the box expires you get one email with the
sign-up link that keeps it. Nothing is stored unless you run this; running
it again replaces the address; --clear withdraws it. The address is used
for that single email and then discarded. Opt in before the final 30
minutes — the reminder is picked up inside that window.`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if remindMeClear {
			if len(args) != 0 {
				return errors.New("--clear takes no address")
			}
			if err := writeRemindMe(""); err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), "Reminder withdrawn.")
			return nil
		}
		if len(args) != 1 {
			return errors.New("usage: containarium remind-me <email>  (or --clear)")
		}
		email, err := normalizeEmail(args[0])
		if err != nil {
			return err
		}
		if err := writeRemindMe(email); err != nil {
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "OK — one reminder with the sign-up link goes to %s about 30 minutes before this box expires.\n", email)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(remindMeCmd)
	remindMeCmd.Flags().BoolVar(&remindMeClear, "clear", false, "Withdraw a reminder you asked for")
}

// normalizeEmail accepts a bare address only (no display name), lowercased.
func normalizeEmail(s string) (string, error) {
	s = strings.TrimSpace(s)
	addr, err := mail.ParseAddress(s)
	if err != nil || addr.Name != "" || addr.Address != s {
		return "", fmt.Errorf("%q is not a plain email address", s)
	}
	// net/mail accepts "a@b"; a reminder cannot be delivered to a dotless
	// host, so require a real domain.
	domain := s[strings.LastIndex(s, "@")+1:]
	if !strings.Contains(domain, ".") || strings.HasPrefix(domain, ".") || strings.HasSuffix(domain, ".") {
		return "", fmt.Errorf("%q is not a deliverable email address", s)
	}
	return strings.ToLower(addr.Address), nil
}

func writeRemindMe(content string) error {
	if _, err := os.Stat(remindMeFile); errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("this box is not an anonymous box (no %s) — reminders only apply to ssh new.<domain> boxes", remindMeFile)
	}
	if content != "" {
		content += "\n"
	}
	if err := os.WriteFile(remindMeFile, []byte(content), 0o666); err != nil { // #nosec G306 -- the daemon created it world-writable on purpose
		return fmt.Errorf("write %s: %w", remindMeFile, err)
	}
	return nil
}
