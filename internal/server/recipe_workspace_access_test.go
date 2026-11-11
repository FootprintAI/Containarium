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
// mintStatus is the helper's HTTP status (0 = 200). It models curl: with -f a
// status of 400 or more is a failed command (curl exits 22) and prints no
// body; without -f curl prints the body and exits 0 whatever the status.
type workspaceBox struct {
	recipeBoxes // nil: GetWorkspaceAccess uses only ExecWithOutput
	mint        func(call int) (string, error)
	mintStatus  int
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
	case "curl -sf --max-time 3 http://127.0.0.1:9099/__mint", "curl -s --max-time 3 http://127.0.0.1:9099/__mint":
		b.mints++
		out, err := b.mint(b.mints)
		if err == nil && b.mintStatus >= 400 && strings.Contains(cmd, " -sf ") {
			return "", "", errors.New("exit status 22")
		}
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
	box := &workspaceBox{mint: func(int) (string, error) { return chatTok + "\n", nil }}
	resp := getAccess(t, workspaceServer(box, "example.com"))
	if resp.GetToken() != chatTok {
		t.Errorf("token = %q", resp.GetToken())
	}
	if want := "https://deck-chat.example.com/__ws_login?t=" + chatTok; resp.GetUrl() != want {
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

// chatTok has the chat workspace helper's token shape:
// secrets.token_urlsafe(24), 32 base64url characters.
const chatTok = "Zm9vYmFyYmF6cXV4X2NoYXQtdG9rZW4x"

// Review reproduction (#3486 follow-up): a helper at its pending-token cap
// answers 503 "mint refused". curl -s exited 0 on it, and the daemon took the
// error text for a chat token and built .../__ws_login?t=mint+refused with no
// error. An error body never becomes a token or a URL.
func TestGetWorkspaceAccess_MintErrorBodyIsNotAToken(t *testing.T) {
	for _, tc := range []struct {
		name   string
		body   string
		status int
	}{
		{"503 text body", "mint refused\n", 503},
		{"503 json body", `{"error":"mint refused"}` + "\n", 503},
		{"200 text body", "mint refused\n", 200},
		{"200 html body", "<html>not found</html>", 200},
		{"200 short token", "abc", 200},
		{"200 long non-token", "../../%3Cscript%3E/not-a-token-but-long-enough", 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mint := func(int) (string, error) { return tc.body, nil }
			// A slides-agent box (no static token): NotFound, not a URL.
			box := &workspaceBox{mint: mint, mintStatus: tc.status, staticErr: errors.New("no such file")}
			resp, err := workspaceServer(box, "example.com").GetWorkspaceAccess(adminCtx(), &pb.GetWorkspaceAccessRequest{Name: "deck"})
			if status.Code(err) != codes.NotFound {
				t.Fatalf("resp %+v err %v, want NotFound", resp, err)
			}
			// A box that also has a static token falls back to it.
			box = &workspaceBox{mint: mint, mintStatus: tc.status, static: "static-tok\n"}
			resp = getAccess(t, workspaceServer(box, "example.com"))
			if resp.GetToken() != "static-tok" || resp.GetUrl() != "https://deck-workspace.example.com/__ws_login?t=static-tok" {
				t.Errorf("resp = %+v, want the static fallback", resp)
			}
		})
	}
}

// The probe fails on an HTTP error status (curl -f), so a helper's error
// response is a failed probe, exactly like a box with no helper.
func TestGetWorkspaceAccess_MintProbeFailsOnHTTPError(t *testing.T) {
	box := &workspaceBox{mint: func(int) (string, error) { return chatTok, nil }, mintStatus: 503, static: "static-tok"}
	resp := getAccess(t, workspaceServer(box, "example.com"))
	if resp.GetToken() != "static-tok" {
		t.Errorf("token = %q: a 503 body must not be used, even one shaped like a token", resp.GetToken())
	}
	if len(box.commands) == 0 || !strings.Contains(box.commands[0], "curl -sf ") {
		t.Errorf("commands = %q, want the mint probe run with curl -sf", box.commands)
	}
}
