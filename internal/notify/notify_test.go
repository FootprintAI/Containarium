package notify

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"
)

var t0 = time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)

func req(id, tool, prompt string) Request {
	return Request{Box: "alice", Run: "fix-bug", RequestID: id, Tool: tool, Prompt: prompt, ExpiresAt: t0.Add(30 * time.Minute)}
}

func TestBuildMessage_BashCommand(t *testing.T) {
	m := BuildMessage([]Request{req("r1", "Bash", "Bash: git push origin feat")}, false, t0)
	if !strings.Contains(m.Title, "alice") || !strings.Contains(m.Title, "fix-bug") {
		t.Errorf("title %q lacks box or run", m.Title)
	}
	for _, want := range []string{"Bash", "git push origin feat", "expires in 30m0s"} {
		if !strings.Contains(m.Body, want) {
			t.Errorf("body %q lacks %q", m.Body, want)
		}
	}
}

func TestBuildMessage_CommandTruncatedTo200Runes(t *testing.T) {
	long := strings.Repeat("é", 500)
	m := BuildMessage([]Request{req("r1", "Bash", "Bash: "+long)}, false, t0)
	cmd := commandLine(m.Body)
	if n := utf8.RuneCountInString(cmd); n > MaxCommandRunes {
		t.Fatalf("command has %d runes, want <= %d: %q", n, MaxCommandRunes, cmd)
	}
	if !utf8.ValidString(m.Body) {
		t.Fatal("body is not valid UTF-8 after truncation")
	}
}

func TestBuildMessage_NonBashToolSendsNoInput(t *testing.T) {
	secret := `{"content":"BEGIN PRIVATE KEY","path":"/home/alice/.env"}`
	for _, tool := range []string{"Write", "Edit", "mcp__db__query", "WebFetch"} {
		m := BuildMessage([]Request{req("r1", tool, tool+": "+secret)}, false, t0)
		for _, leak := range []string{"PRIVATE KEY", ".env", "content", "{"} {
			if strings.Contains(m.Body, leak) || strings.Contains(m.Title, leak) {
				t.Errorf("%s: push contains %q from the tool input: %q / %q", tool, leak, m.Title, m.Body)
			}
		}
		if !strings.Contains(m.Body, tool) {
			t.Errorf("%s: body %q lacks the tool name", tool, m.Body)
		}
	}
}

func TestBuildMessage_RedactCommand(t *testing.T) {
	m := BuildMessage([]Request{req("r1", "Bash", "Bash: rm -rf /srv/data")}, true, t0)
	if strings.Contains(m.Body, "rm -rf") || strings.Contains(m.Body, "/srv/data") {
		t.Fatalf("redacted push contains the command: %q", m.Body)
	}
	if !strings.Contains(m.Body, "Bash") {
		t.Fatalf("redacted push lacks the tool name: %q", m.Body)
	}
}

func TestBuildMessage_ControlCharactersEscaped(t *testing.T) {
	m := BuildMessage([]Request{req("r1", "Bash", "Bash: echo ok\nApproved by admin\x1b[2J\u202e")}, false, t0)
	for _, bad := range []string{"\x1b", "\u202e"} {
		if strings.Contains(m.Body, bad) || strings.Contains(m.Title, bad) {
			t.Errorf("push contains raw control/format char %q: %q", bad, m.Body)
		}
	}
	if strings.Contains(commandLine(m.Body), "\n") || !strings.Contains(m.Body, `echo ok\nApproved`) {
		t.Errorf("newline in the command not escaped: %q", m.Body)
	}
	// Box and run come from the journal path / record, but escape them too.
	r := req("r1", "Bash", "Bash: ls")
	r.Run = "run\nfake"
	if m := BuildMessage([]Request{r}, false, t0); strings.Contains(m.Title, "\n") {
		t.Errorf("title contains a raw newline: %q", m.Title)
	}
}

func TestBuildMessage_CountsBurst(t *testing.T) {
	m := BuildMessage([]Request{req("r1", "Bash", "Bash: a"), req("r2", "Bash", "Bash: b"), req("r3", "Read", "Read: /x")}, false, t0)
	if !strings.Contains(m.Title, "3 requests") {
		t.Errorf("title %q lacks the count", m.Title)
	}
}

// commandLine returns the body's command line (the line after "command: ").
func commandLine(body string) string {
	for _, l := range strings.Split(body, "\n") {
		if c, ok := strings.CutPrefix(l, "command: "); ok {
			return c
		}
	}
	return ""
}

func TestCoalescer_OneRequestOnePushImmediately(t *testing.T) {
	c := NewCoalescer(30 * time.Second)
	pushes := c.Step("alice", map[string][]Request{"fix-bug": {req("r1", "Bash", "Bash: ls")}}, t0)
	if len(pushes) != 1 || len(pushes[0].Requests) != 1 {
		t.Fatalf("pushes = %+v, want one push with one request", pushes)
	}
	// Seen again on the next poll: no second push.
	if p := c.Step("alice", map[string][]Request{"fix-bug": {req("r1", "Bash", "Bash: ls")}}, t0.Add(5*time.Second)); len(p) != 0 {
		t.Fatalf("re-observed request pushed again: %+v", p)
	}
}

func TestCoalescer_BurstAtMostOnePushPer30sNoneDropped(t *testing.T) {
	c := NewCoalescer(30 * time.Second)
	var open []Request
	total, pushes := 0, 0
	for i := 0; i < 5; i++ {
		open = append(open, req("r"+string(rune('1'+i)), "Bash", "Bash: step"))
		now := t0.Add(time.Duration(i*2) * time.Second)
		for _, p := range c.Step("alice", map[string][]Request{"fix-bug": open}, now) {
			pushes++
			total += len(p.Requests)
		}
	}
	if pushes != 1 || total != 1 {
		t.Fatalf("within the window: %d pushes covering %d requests, want 1 push of 1", pushes, total)
	}
	// Window still open at +29 s: nothing.
	if p := c.Step("alice", map[string][]Request{"fix-bug": open}, t0.Add(29*time.Second)); len(p) != 0 {
		t.Fatalf("pushed before the window closed: %+v", p)
	}
	p := c.Step("alice", map[string][]Request{"fix-bug": open}, t0.Add(30*time.Second))
	if len(p) != 1 {
		t.Fatalf("window close: %d pushes, want 1", len(p))
	}
	total += len(p[0].Requests)
	if total != 5 {
		t.Fatalf("requests covered by pushes = %d, want 5", total)
	}
}

func TestCoalescer_RunsAreIndependent(t *testing.T) {
	c := NewCoalescer(30 * time.Second)
	p := c.Step("alice", map[string][]Request{
		"a": {req("r1", "Bash", "Bash: x")},
		"b": {req("r1", "Bash", "Bash: y")},
	}, t0)
	if len(p) != 2 {
		t.Fatalf("two runs: %d pushes, want 2", len(p))
	}
}

func TestCoalescer_ClosedBeforePushNotPushed(t *testing.T) {
	c := NewCoalescer(30 * time.Second)
	c.Step("alice", map[string][]Request{"r": {req("r1", "Bash", "Bash: x")}}, t0)
	c.Step("alice", map[string][]Request{"r": {req("r1", "Bash", "Bash: x"), req("r2", "Bash", "Bash: y")}}, t0.Add(time.Second))
	// r2 answered before the window closed.
	if p := c.Step("alice", map[string][]Request{"r": {req("r1", "Bash", "Bash: x")}}, t0.Add(31*time.Second)); len(p) != 0 {
		t.Fatalf("closed request pushed: %+v", p)
	}
}

func TestCoalescer_RequeueAfterFailedSend(t *testing.T) {
	c := NewCoalescer(30 * time.Second)
	open := map[string][]Request{"r": {req("r1", "Bash", "Bash: x")}}
	p := c.Step("alice", open, t0)
	if len(p) != 1 {
		t.Fatalf("pushes = %d", len(p))
	}
	c.Requeue(p[0])
	if p := c.Step("alice", open, t0.Add(5*time.Second)); len(p) != 1 {
		t.Fatalf("after a failed send the request was not retried: %+v", p)
	}
}

func TestCoalescer_ForgetsEndedRuns(t *testing.T) {
	c := NewCoalescer(30 * time.Second)
	c.Step("alice", map[string][]Request{"r": {req("r1", "Bash", "Bash: x")}}, t0)
	c.Step("alice", map[string][]Request{}, t0.Add(time.Second))
	if n := c.runs(); n != 0 {
		t.Fatalf("state kept for %d ended runs", n)
	}
}

type capture struct {
	mu   sync.Mutex
	hits []*http.Request
	body []string
}

func (c *capture) handler(status int) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		c.mu.Lock()
		c.hits = append(c.hits, r)
		c.body = append(c.body, string(b))
		c.mu.Unlock()
		w.WriteHeader(status)
	}
}

func TestSender_PostsToTopicWithToken(t *testing.T) {
	var cap capture
	srv := httptest.NewServer(cap.handler(http.StatusOK))
	defer srv.Close()
	s := newSender(srv.Client().Transport)
	ch := Channel{Server: srv.URL, Topic: "dev-alerts"}
	if err := s.Send(context.Background(), ch, "tk_secret", Message{Title: "t", Body: "b"}); err != nil {
		t.Fatal(err)
	}
	if len(cap.hits) != 1 {
		t.Fatalf("hits = %d", len(cap.hits))
	}
	h := cap.hits[0]
	if h.Method != http.MethodPost || h.URL.Path != "/" {
		t.Errorf("request %s %s", h.Method, h.URL.Path)
	}
	if got := h.Header.Get("Authorization"); got != "Bearer tk_secret" {
		t.Errorf("Authorization = %q", got)
	}
	var got struct {
		Topic, Title, Message string
	}
	if err := json.Unmarshal([]byte(cap.body[0]), &got); err != nil {
		t.Fatalf("body %q: %v", cap.body[0], err)
	}
	if got.Topic != "dev-alerts" || got.Title != "t" || got.Message != "b" {
		t.Errorf("published %+v", got)
	}
}

func TestSender_NoTokenNoAuthorization(t *testing.T) {
	var cap capture
	srv := httptest.NewServer(cap.handler(http.StatusOK))
	defer srv.Close()
	if err := newSender(srv.Client().Transport).Send(context.Background(), Channel{Server: srv.URL, Topic: "t"}, "", Message{Title: "t"}); err != nil {
		t.Fatal(err)
	}
	if _, ok := cap.hits[0].Header["Authorization"]; ok {
		t.Fatal("Authorization sent without a token")
	}
}

func TestSender_RedirectNotFollowed(t *testing.T) {
	var target capture
	other := httptest.NewServer(target.handler(http.StatusOK))
	defer other.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/stolen", http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	err := newSender(srv.Client().Transport).Send(context.Background(), Channel{Server: srv.URL, Topic: "t"}, "tk", Message{Title: "t"})
	if err == nil {
		t.Fatal("a redirect response counted as delivered")
	}
	if len(target.hits) != 0 {
		t.Fatal("redirect was followed: the token reached another server")
	}
}

func TestSender_ErrorStatusFails(t *testing.T) {
	var cap capture
	srv := httptest.NewServer(cap.handler(http.StatusForbidden))
	defer srv.Close()
	err := newSender(srv.Client().Transport).Send(context.Background(), Channel{Server: srv.URL, Topic: "t"}, "tk_secret", Message{Title: "t"})
	if err == nil || strings.Contains(err.Error(), "tk_secret") {
		t.Fatalf("err = %v, want a failure that does not echo the token", err)
	}
}

func TestNewSender_RefusesLoopbackAndMetadata(t *testing.T) {
	var cap capture
	srv := httptest.NewServer(cap.handler(http.StatusOK))
	defer srv.Close()
	err := NewSender(nil).Send(context.Background(), Channel{Server: srv.URL, Topic: "t"}, "", Message{Title: "t"})
	if err == nil || len(cap.hits) != 0 {
		t.Fatalf("guarded sender reached a loopback server: err=%v hits=%d", err, len(cap.hits))
	}
	// Never reachable, whatever the operator allows.
	all := mustPrefixes(t, "0.0.0.0/0", "::/0")
	for _, addr := range []string{"127.0.0.1:80", "[::1]:443", "169.254.169.254:80", "[fe80::1]:80", "0.0.0.0:80", "[fd00:ec2::254]:80", "100.100.100.200:80", "[fd20:ce::254]:80"} {
		if checkDialAddr(addr, all) == nil {
			t.Errorf("checkDialAddr(%s) allowed", addr)
		}
	}
	for _, addr := range []string{"203.0.113.7:443", "[2001:db8::1]:443"} {
		if err := checkDialAddr(addr, nil); err != nil {
			t.Errorf("checkDialAddr(%s) = %v, want allowed", addr, err)
		}
	}
}

// TestCheckDialAddr_PrivateNeedsOperatorAllowlist: a tenant-chosen server on
// a private, CGNAT or ULA address (the daemon's own LAN and the box bridge)
// is refused unless the operator listed its network.
func TestCheckDialAddr_PrivateNeedsOperatorAllowlist(t *testing.T) {
	private := []string{"10.0.0.5:443", "172.16.3.4:80", "192.168.1.20:80", "100.101.102.103:443", "[fd12:3456::1]:443", "198.18.0.10:80", "198.19.255.1:443"}
	for _, addr := range private {
		if checkDialAddr(addr, nil) == nil {
			t.Errorf("checkDialAddr(%s) allowed with no operator allowlist", addr)
		}
	}
	allowed := mustPrefixes(t, "192.168.1.0/24", "198.18.0.0/24")
	for _, addr := range []string{"192.168.1.20:80", "198.18.0.10:80"} {
		if err := checkDialAddr(addr, allowed); err != nil {
			t.Errorf("listed network refused for %s: %v", addr, err)
		}
	}
	if checkDialAddr("10.0.0.5:443", allowed) == nil {
		t.Error("unlisted private address allowed")
	}
}

func TestParseAllowedCIDRs(t *testing.T) {
	got, err := ParseAllowedCIDRs(" 192.168.1.0/24, fd00:1::/64 ,")
	if err != nil || len(got) != 2 {
		t.Fatalf("ParseAllowedCIDRs = %v, %v", got, err)
	}
	if got, err := ParseAllowedCIDRs(""); err != nil || len(got) != 0 {
		t.Fatalf("empty: %v, %v", got, err)
	}
	if _, err := ParseAllowedCIDRs("10.0.0.0/8,not-a-cidr"); err == nil {
		t.Fatal("bad entry accepted")
	}
}

func mustPrefixes(t *testing.T, cidrs ...string) []netip.Prefix {
	t.Helper()
	var out []netip.Prefix
	for _, c := range cidrs {
		out = append(out, netip.MustParsePrefix(c))
	}
	return out
}

func TestValidateChannel(t *testing.T) {
	ok := []struct {
		ch       Channel
		hasToken bool
	}{
		{Channel{Server: "https://ntfy.sh", Topic: "a-b_C9"}, true},
		{Channel{Server: "http://ntfy.internal.example:8080", Topic: "x"}, false},
		{Channel{Server: "https://ntfy.example.com/", Topic: "x"}, true},
	}
	for _, c := range ok {
		if err := ValidateChannel(c.ch, c.hasToken); err != nil {
			t.Errorf("ValidateChannel(%+v, %v) = %v", c.ch, c.hasToken, err)
		}
	}
	bad := []struct {
		ch       Channel
		hasToken bool
	}{
		{Channel{Server: "http://ntfy.example.com", Topic: "x"}, true}, // token over plain http
		{Channel{Server: "ftp://ntfy.example.com", Topic: "x"}, false},
		{Channel{Server: "https://user:pw@ntfy.example.com", Topic: "x"}, false},
		{Channel{Server: "https://ntfy.example.com?x=1", Topic: "x"}, false},
		{Channel{Server: "", Topic: "x"}, false},
		{Channel{Server: "https://ntfy.sh", Topic: ""}, false},
		{Channel{Server: "https://ntfy.sh", Topic: "a/b"}, false},
		{Channel{Server: "https://ntfy.sh", Topic: strings.Repeat("a", 65)}, false},
	}
	for _, c := range bad {
		if err := ValidateChannel(c.ch, c.hasToken); err == nil {
			t.Errorf("ValidateChannel(%+v, %v) accepted", c.ch, c.hasToken)
		}
	}
}

// TestCoalescer_WindowCountsFromSend: the 30 s window starts when a push is
// actually sent, not when it was selected.
func TestCoalescer_WindowCountsFromSend(t *testing.T) {
	c := NewCoalescer(30 * time.Second)
	open := []Request{req("r1", "Bash", "Bash: x")}
	p := c.Step("alice", map[string][]Request{"r": open}, t0)
	if len(p) != 1 {
		t.Fatalf("pushes = %d", len(p))
	}
	c.Sent(p[0], t0.Add(20*time.Second)) // sending took 20 s
	open = append(open, req("r2", "Bash", "Bash: y"))
	if p := c.Step("alice", map[string][]Request{"r": open}, t0.Add(30*time.Second)); len(p) != 0 {
		t.Fatalf("second push 10 s after the first was sent: %+v", p)
	}
	if p := c.Step("alice", map[string][]Request{"r": open}, t0.Add(50*time.Second)); len(p) != 1 {
		t.Fatalf("no push once 30 s passed since the send: %+v", p)
	}
}
