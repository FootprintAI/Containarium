package server

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// workspaceBox is a recipeBoxes fake for GetWorkspaceAccess: it answers the
// in-box mint probe and the static-token read, and records every command.
type workspaceBox struct {
	recipeBoxes // nil: GetWorkspaceAccess uses only ExecWithOutput
	mint        func(call int) (string, error)
	static      string
	staticErr   error
	mints       int
	commands    []string
}

func (b *workspaceBox) ExecWithOutput(name string, command []string) (string, string, error) {
	if name != "deck-container" {
		return "", "", fmt.Errorf("unexpected box %q", name)
	}
	cmd := strings.Join(command, " ")
	b.commands = append(b.commands, cmd)
	switch cmd {
	case "curl -s --max-time 3 http://127.0.0.1:9099/__mint":
		b.mints++
		out, err := b.mint(b.mints)
		return out, "", err
	case "cat /opt/wsauth/token":
		return b.static, "", b.staticErr
	}
	return "", "", fmt.Errorf("unexpected command %q", cmd)
}

func workspaceServer(box *workspaceBox, baseDomain string) *RecipeServer {
	srv := &RecipeServer{boxes: box}
	if baseDomain != "" {
		srv.network = &NetworkServer{baseDomain: baseDomain}
	}
	return srv
}

func slidesToken(call int) string { return fmt.Sprintf("%042d%d", 0, call%10) }

func getAccess(t *testing.T, srv *RecipeServer) *pb.GetWorkspaceAccessResponse {
	t.Helper()
	resp, err := srv.GetWorkspaceAccess(adminCtx(), &pb.GetWorkspaceAccessRequest{Name: "deck"})
	if err != nil {
		t.Fatalf("GetWorkspaceAccess: %v", err)
	}
	return resp
}

// A slides-agent box mints a fresh single-use token per call; the URL carries
// it in the fragment on the box's workspace subdomain, never in the query.
func TestGetWorkspaceAccess_SlidesAgentMintsPerCall(t *testing.T) {
	box := &workspaceBox{
		mint:   func(call int) (string, error) { return `{"token":"` + slidesToken(call) + `"}` + "\n", nil },
		static: "static-must-not-be-used",
	}
	srv := workspaceServer(box, "example.com")
	first, second := getAccess(t, srv), getAccess(t, srv)
	if first.GetToken() != slidesToken(1) || second.GetToken() != slidesToken(2) {
		t.Fatalf("tokens %q, %q: want a fresh minted token per call", first.GetToken(), second.GetToken())
	}
	if want := "https://deck-workspace.example.com/__ws_login#t=" + slidesToken(1); first.GetUrl() != want {
		t.Errorf("url = %q, want %q", first.GetUrl(), want)
	}
	if strings.Contains(first.GetUrl(), "?") {
		t.Errorf("url %q carries a query", first.GetUrl())
	}
	for _, c := range box.commands {
		if strings.HasPrefix(c, "cat ") {
			t.Errorf("a minted token must not fall back to the static token: ran %q", c)
		}
	}
}

// When the probe fails, or answers a body that is not a well-formed slides
// mint, the static token is used as before (agent-workspace, and slides-agent
// boxes created before the helper existed).
func TestGetWorkspaceAccess_FallsBackToStaticToken(t *testing.T) {
	for name, mint := range map[string]func(int) (string, error){
		"probe fails":        func(int) (string, error) { return "", errors.New("exit status 7") },
		"probe empty":        func(int) (string, error) { return "  \n", nil },
		"token too short":    func(int) (string, error) { return `{"token":"abc"}`, nil },
		"token with query":   func(int) (string, error) { return `{"token":"` + strings.Repeat("a", 40) + `&x="}`, nil },
		"not json":           func(int) (string, error) { return `{"token":`, nil },
		"json without token": func(int) (string, error) { return `{"error":"mint refused"}`, nil },
	} {
		t.Run(name, func(t *testing.T) {
			srv := workspaceServer(&workspaceBox{mint: mint, static: "static-tok\n"}, "example.com")
			resp := getAccess(t, srv)
			if resp.GetToken() != "static-tok" {
				t.Errorf("token = %q, want the static token", resp.GetToken())
			}
			if want := "https://deck-workspace.example.com/__ws_login?t=static-tok"; resp.GetUrl() != want {
				t.Errorf("url = %q, want %q", resp.GetUrl(), want)
			}
		})
	}
}

// The chat workspace's helper prints the bare token: unchanged, ?t= on the
// chat subdomain.
func TestGetWorkspaceAccess_ChatWorkspaceUnchanged(t *testing.T) {
	box := &workspaceBox{mint: func(int) (string, error) { return "chat-tok_1\n", nil }}
	resp := getAccess(t, workspaceServer(box, "example.com"))
	if resp.GetToken() != "chat-tok_1" {
		t.Errorf("token = %q", resp.GetToken())
	}
	if want := "https://deck-chat.example.com/__ws_login?t=chat-tok_1"; resp.GetUrl() != want {
		t.Errorf("url = %q, want %q", resp.GetUrl(), want)
	}
	if len(box.commands) != 1 {
		t.Errorf("commands = %q, want only the mint probe", box.commands)
	}
}

func TestGetWorkspaceAccess_NoBaseDomainReturnsTokenOnly(t *testing.T) {
	box := &workspaceBox{mint: func(call int) (string, error) { return `{"token":"` + slidesToken(call) + `"}`, nil }}
	resp := getAccess(t, workspaceServer(box, ""))
	if resp.GetToken() != slidesToken(1) || resp.GetUrl() != "" {
		t.Errorf("resp = %+v, want the token and no URL", resp)
	}
}

func TestGetWorkspaceAccess_NoTokenIsNotFound(t *testing.T) {
	for name, box := range map[string]*workspaceBox{
		"no static file": {mint: func(int) (string, error) { return "", errors.New("exit 7") }, staticErr: errors.New("no such file")},
		"empty static":   {mint: func(int) (string, error) { return "", errors.New("exit 7") }, static: "\n"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := workspaceServer(box, "example.com").GetWorkspaceAccess(adminCtx(), &pb.GetWorkspaceAccessRequest{Name: "deck"})
			if status.Code(err) != codes.NotFound {
				t.Fatalf("err = %v, want NotFound", err)
			}
		})
	}
}

func TestParseWorkspaceMint(t *testing.T) {
	good := strings.Repeat("A", 42) + "_"
	for body, want := range map[string]string{
		`{"token":"` + good + `"}`:           good,
		`{"token":"` + good + `","extra":1}`: good,
		`{"token":"` + good + `x"}`:          "",
		`{"token":"` + good[:42] + `="}`:     "",
		`{"token":""}`:                       "",
		`["` + good + `"]`:                   "",
		good:                                 "",
	} {
		if got := parseWorkspaceMint(body); got != want {
			t.Errorf("parseWorkspaceMint(%q) = %q, want %q", body, got, want)
		}
	}
}
