package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/footprintai/containarium/internal/client"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
	"github.com/spf13/cobra"
)

// tracker change submit-files (#3005) — opens a change request from a
// file set over the connection's broker credential, with no run box.
var trackerChangeSubmitFilesCmd = &cobra.Command{
	Use:   "submit-files <username> <connection> <issue>",
	Short: "Open a change request from local files over the connection's broker credential",
	Long: `Sends whole files to the daemon, which fetches the base branch from the
connection's remote on the host with the broker credential, commits the
files on top of it, pushes the head branch (never forced) and opens a
change request referencing issue. Needs tracker:write on the tenant, not
a run-scoped token. Each --file is <repo-path>=<local-file>.

Example:
  containarium tracker change submit-files alice default 42 \
    --title "Fix the flaky retry test" \
    --file internal/retry/retry.go=./retry.go \
    --head containarium/issue-42`,
	Args: cobra.ExactArgs(3),
	RunE: runTrackerChangeSubmitFiles,
}

var (
	trackerSubmitFilesTitle       string
	trackerSubmitFilesDescription string
	trackerSubmitFilesDraft       bool
	trackerSubmitFilesBase        string
	trackerSubmitFilesHead        string
	trackerSubmitFilesFiles       []string
)

func init() {
	trackerChangeCmd.AddCommand(trackerChangeSubmitFilesCmd)
	f := trackerChangeSubmitFilesCmd.Flags()
	f.StringVar(&trackerSubmitFilesTitle, "title", "", "Change request title and commit subject (required)")
	f.StringVar(&trackerSubmitFilesDescription, "description", "", "Change request description")
	f.BoolVar(&trackerSubmitFilesDraft, "draft", false, "Open as a draft/WIP")
	f.StringVar(&trackerSubmitFilesBase, "base", "", "Base branch (default: the project's default branch)")
	f.StringVar(&trackerSubmitFilesHead, "head", "", "Head branch to push (default: a daemon-chosen branch stable for this issue and title)")
	f.StringArrayVar(&trackerSubmitFilesFiles, "file", nil, "<repo-path>=<local-file>, repeatable (at least one)")
	_ = trackerChangeSubmitFilesCmd.MarkFlagRequired("title")
	_ = trackerChangeSubmitFilesCmd.MarkFlagRequired("file")
}

// parseChangeFileFlags turns --file <repo-path>=<local-file> values into
// request files, reading each local file with readFile. Path validation
// is the daemon's; this only splits and reads.
func parseChangeFileFlags(specs []string, readFile func(string) ([]byte, error)) ([]*pb.TrackerChangeFile, error) {
	files := make([]*pb.TrackerChangeFile, 0, len(specs))
	for _, spec := range specs {
		repoPath, local, ok := strings.Cut(spec, "=")
		if !ok || repoPath == "" || local == "" {
			return nil, fmt.Errorf("--file %q: want <repo-path>=<local-file>", spec)
		}
		content, err := readFile(local)
		if err != nil {
			return nil, fmt.Errorf("--file %q: %w", spec, err)
		}
		files = append(files, &pb.TrackerChangeFile{Path: repoPath, Content: string(content)})
	}
	return files, nil
}

func runTrackerChangeSubmitFiles(cmd *cobra.Command, args []string) error {
	username, connection := args[0], args[1]
	issue, err := parseTrackerIssueNumber(args[2])
	if err != nil {
		return err
	}
	if serverAddr == "" {
		return fmt.Errorf("--server is required for tracker commands")
	}
	files, err := parseChangeFileFlags(trackerSubmitFilesFiles, os.ReadFile)
	if err != nil {
		return err
	}

	req := &pb.SubmitTrackerChangeFilesRequest{
		Username:    username,
		Connection:  connection,
		Issue:       issue,
		Title:       trackerSubmitFilesTitle,
		Description: trackerSubmitFilesDescription,
		Draft:       trackerSubmitFilesDraft,
		BaseRef:     trackerSubmitFilesBase,
		HeadBranch:  trackerSubmitFilesHead,
		Files:       files,
	}
	var change *pb.TrackerChange
	if httpMode {
		h, err := client.NewHTTPClient(serverAddr, authToken)
		if err != nil {
			return err
		}
		defer func() { _ = h.Close() }()
		if change, err = h.SubmitTrackerChangeFiles(req); err != nil {
			return err
		}
	} else {
		g, err := client.NewGRPCClient(serverAddr, certsDir, insecure)
		if err != nil {
			return err
		}
		defer func() { _ = g.Close() }()
		if change, err = g.SubmitTrackerChangeFiles(req); err != nil {
			return err
		}
	}

	fmt.Printf("#%d opened on branch %s\n", change.GetNumber(), change.GetBranch())
	if change.GetUrl() != "" {
		fmt.Printf("url: %s\n", change.GetUrl())
	}
	return nil
}
