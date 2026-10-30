package server

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/footprintai/containarium/internal/proofpack"
	"github.com/footprintai/containarium/internal/tracker"
	"github.com/footprintai/containarium/internal/tracker/submit"
	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// fakeProofBox is a proofpack.Execer standing in for the run's box: the
// probe reports probeRC (12: a Makefile, no declaration, so `make test`
// runs), the one step prints "PASS", and HEAD is commit.
type fakeProofBox struct {
	commit  string
	probeRC int
	ran     []string
}

func (f *fakeProofBox) ExecWithExitCode(box string, argv []string) (string, string, int, error) {
	f.ran = append(f.ran, box)
	switch {
	case len(argv) > 3 && argv[3] == "proofpack-probe":
		return "", "", f.probeRC, nil
	case len(argv) > 0 && argv[0] == "git":
		return f.commit + "\n", "", 0, nil
	default:
		return "PASS\n", "5\n", 0, nil
	}
}

// A tracker-dispatched PR carries the sealed pack as a file in its branch
// and the pack digest in its description, and the file verifies against the
// audit chain; editing one log byte makes verify fail and name the step.
func TestSubmitTrackerChange_AttachesSealedProofPack(t *testing.T) {
	user := "tracker-rpc-submit-proofpack-" + uuid.NewString()
	bundleBytes, headSHA := realBundleBytes(t)
	provider := &fakeWriterProvider{openChangeOut: tracker.Change{Number: 8, URL: "https://github.com/acme/widgets/pull/8"}}
	info := validRunInfo()
	box := &fakeSubmitBox{bundleBytes: bundleBytes, headSHA: headSHA}
	pusher := &fakeSubmitPusher{result: submit.PushResult{Branch: "agent/b", SHA: strings.Repeat("d", 40)}}
	s, ctx := setUpSubmitConnection(t, user, provider, box, pusher, &info)

	if _, err := s.SubmitTrackerChange(ctx, &pb.SubmitTrackerChangeRequest{
		Username: user, Connection: "default", Issue: 1, Title: "My change", Description: "does the thing",
	}); err != nil {
		t.Fatalf("SubmitTrackerChange: %v", err)
	}

	files := pusher.gotSpec.Files
	if len(files) != 1 || files[0].Path != proofpack.AttachPath {
		t.Fatalf("pushed files = %v, want one at %s", files, proofpack.AttachPath)
	}
	var sealed pb.SealedProofPack
	if err := protojson.Unmarshal(files[0].Content, &sealed); err != nil {
		t.Fatalf("attached file is not a SealedProofPack: %v", err)
	}
	pack := sealed.GetPack()
	if pack.GetProducer() != info.Box || pack.GetRepoDir() != info.Workspace || pack.GetGitCommit() != headSHA {
		t.Errorf("pack producer/dir/commit = %q %q %q, want the run's box, workspace and bundled head",
			pack.GetProducer(), pack.GetRepoDir(), pack.GetGitCommit())
	}
	if len(pack.GetSteps()) != 1 || pack.GetStatus() != pb.ProofPackStatus_PROOF_PACK_STATUS_PASSED {
		t.Errorf("pack steps/status = %d %s", len(pack.GetSteps()), pack.GetStatus())
	}
	if !strings.Contains(pusher.gotSpec.FilesMessage, sealed.GetSeal().GetPackSha256()) {
		t.Errorf("files commit message %q does not carry the digest", pusher.gotSpec.FilesMessage)
	}

	desc := provider.openChangeReq.Description
	if !strings.Contains(desc, "sha256:"+sealed.GetSeal().GetPackSha256()) || !strings.Contains(desc, proofpack.AttachPath) {
		t.Errorf("description %q does not carry the pack digest and file", desc)
	}
	if !strings.Contains(desc, "Closes #1") || !strings.Contains(desc, "via Containarium") {
		t.Errorf("description %q lost the closing reference or stamp", desc)
	}

	res, err := proofpack.Verify(context.Background(), s.auditStore, &sealed)
	if err != nil {
		t.Fatalf("Verify the attached pack: %v", err)
	}
	if res.AuditRowID != sealed.GetSeal().GetAuditRowId() {
		t.Errorf("verified row %d, want %d", res.AuditRowID, sealed.GetSeal().GetAuditRowId())
	}
	row, ok, err := s.auditStore.ChainEntryAt(context.Background(), res.AuditRowID)
	if err != nil || !ok || row.Username != user || row.RunID != "run-abc123" {
		t.Errorf("seal row = %+v ok=%v err=%v, want attributed to the user and run", row, ok, err)
	}

	sealed.Pack.Steps[0].Log[0] ^= 1
	_, err = proofpack.Verify(context.Background(), s.auditStore, &sealed)
	var tp *proofpack.TamperedPart
	if !errors.As(err, &tp) || tp.Name != "make-test" {
		t.Errorf("Verify after editing a log byte: %v, want step \"make-test\" named", err)
	}
}

// No PR opens without its pack: a failure to generate or seal it stops the
// submit before anything is pushed.
func TestSubmitTrackerChange_ProofPackBlocksSubmit(t *testing.T) {
	cases := []struct {
		name  string
		setup func(s *ContainerServer, headSHA string)
		code  codes.Code
		msg   string
	}{
		{"generation fails", func(s *ContainerServer, h string) { s.proofPackExecer = &fakeProofBox{commit: h, probeRC: 97} }, codes.FailedPrecondition, "generate proof pack"},
		{"workspace HEAD moved", func(s *ContainerServer, _ string) {
			s.proofPackExecer = &fakeProofBox{commit: strings.Repeat("e", 40), probeRC: 12}
		}, codes.FailedPrecondition, "the workspace moved"},
		{"no audit store to seal into", func(s *ContainerServer, _ string) { s.auditStore = nil }, codes.Unavailable, "without sealing its proof pack"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			user := "tracker-rpc-submit-proofpack-block-" + uuid.NewString()
			bundleBytes, headSHA := realBundleBytes(t)
			provider := &fakeWriterProvider{openChangeOut: tracker.Change{Number: 9}}
			info := validRunInfo()
			pusher := &fakeSubmitPusher{result: submit.PushResult{Branch: "agent/b", SHA: headSHA}}
			s, ctx := setUpSubmitConnection(t, user, provider, &fakeSubmitBox{bundleBytes: bundleBytes, headSHA: headSHA}, pusher, &info)
			tc.setup(s, headSHA)

			_, err := s.SubmitTrackerChange(ctx, &pb.SubmitTrackerChangeRequest{
				Username: user, Connection: "default", Issue: 1, Title: "My change",
			})
			if status.Code(err) != tc.code || !strings.Contains(err.Error(), tc.msg) {
				t.Fatalf("err = %v, want %s mentioning %q", err, tc.code, tc.msg)
			}
			if pusher.gotSpec.HeadSHA != "" {
				t.Errorf("pushed %+v although the pack was not sealed", pusher.gotSpec)
			}
			if provider.openChangeReq.Title != "" {
				t.Errorf("opened a change although the pack was not sealed")
			}
		})
	}
}
