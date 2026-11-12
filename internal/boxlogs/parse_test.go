package boxlogs

import (
	"fmt"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

const (
	testID0 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	testID1 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

// jcur is a journal cursor of the shape journald prints, for entry seq.
func jcur(seq int) string {
	return fmt.Sprintf("s=0123456789abcdef0123456789abcdef;i=%x;b=fedcba9876543210fedcba9876543210;m=%x;t=%x;x=%x", seq, seq, seq, seq)
}

// jframe is one journal frame as `journalctl -o json` prints it, behind "J ".
func jframe(seq int, t time.Time, unit, msg string) string {
	return fmt.Sprintf(`J {"__CURSOR":%q,"__REALTIME_TIMESTAMP":"%d","__MONOTONIC_TIMESTAMP":"1","_BOOT_ID":"x","_SYSTEMD_UNIT":%q,"MESSAGE":%q}`,
		jcur(seq), t.UnixMicro(), unit, msg)
}

// dframe is one docker line as `docker logs -t` prints it, behind "D <idx> ".
func dframe(idx int, t time.Time, text string) string {
	return fmt.Sprintf("D %d %s %s", idx, t.UTC().Format(time.RFC3339Nano), text)
}

var t0 = time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC)

// output assembles a script output: header, then frames, one per line.
func output(frames ...string) string {
	head := []string{"V 1", fmt.Sprintf("N %d", t0.Add(time.Hour).UnixNano()), "R docker",
		"U nginx.service", "U cron.service",
		"C 0 " + testID0 + " web running", "C 1 " + testID1 + " worker exited",
		"L 1000 1000"}
	return strings.Join(append(head, frames...), "\n") + "\n"
}

func TestParse_ReadsEveryFrameKind(t *testing.T) {
	out := output(
		jframe(1, t0, "nginx.service", "started"),
		"E J 0",
		dframe(0, t0.Add(time.Millisecond), "GET /"),
		"E D 0 0",
		"E D 1 0",
	)
	c, err := Parse(out)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if c.Runtime != pb.BoxContainerRuntime_BOX_CONTAINER_RUNTIME_DOCKER {
		t.Errorf("runtime = %v", c.Runtime)
	}
	if !c.Now.Equal(t0.Add(time.Hour)) {
		t.Errorf("now = %v", c.Now)
	}
	if fmt.Sprint(c.Units) != "[nginx.service cron.service]" {
		t.Errorf("units = %v", c.Units)
	}
	if len(c.Containers) != 2 || c.Containers[0].Name != "web" || c.Containers[1].ID != testID1 || c.Containers[1].State != "exited" {
		t.Errorf("containers = %+v", c.Containers)
	}
	if c.JournalLimit != 1000 || c.ContainerLimit != 1000 {
		t.Errorf("limits = %d %d", c.JournalLimit, c.ContainerLimit)
	}
	if !c.Journal.Ended || len(c.Journal.Lines) != 1 {
		t.Fatalf("journal = %+v", c.Journal)
	}
	j := c.Journal.Lines[0]
	if j.Source != "nginx.service" || j.Text != "started" || !j.Time.Equal(t0) || j.Kind != pb.BoxLogSourceKind_BOX_LOG_SOURCE_KIND_JOURNAL || j.journalCursor != jcur(1) {
		t.Errorf("journal line = %+v", j)
	}
	r := c.ContainerReads[0]
	if r == nil || !r.Ended || len(r.Lines) != 1 {
		t.Fatalf("container 0 = %+v", r)
	}
	d := r.Lines[0]
	if d.Source != "web" || d.Text != "GET /" || !d.Time.Equal(t0.Add(time.Millisecond)) || d.Kind != pb.BoxLogSourceKind_BOX_LOG_SOURCE_KIND_CONTAINER || d.containerID != testID0 {
		t.Errorf("container line = %+v", d)
	}
	if c.Dropped != 0 {
		t.Errorf("dropped = %d", c.Dropped)
	}
}

// The journal names a line by its unit, else its syslog identifier.
func TestParse_JournalLabel(t *testing.T) {
	out := output(
		fmt.Sprintf(`J {"__CURSOR":%q,"__REALTIME_TIMESTAMP":"%d","SYSLOG_IDENTIFIER":"kernel","MESSAGE":"oops"}`, jcur(2), t0.UnixMicro()),
		"E J 0")
	c, err := Parse(out)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Journal.Lines) != 1 || c.Journal.Lines[0].Source != "kernel" {
		t.Fatalf("lines = %+v", c.Journal.Lines)
	}
}

// Hostile output: a box's root can print anything. Nothing it prints may
// break the parse of other frames or produce a line over the caps.
func TestParse_HostileFrames(t *testing.T) {
	mb := strings.Repeat("A", 1<<20)
	cases := []struct {
		name        string
		frame       string
		wantLines   int // lines parsed from the hostile frame
		wantText    string
		wantTrunc   bool
		wantDropped int
	}{
		{name: "control bytes", frame: dframe(0, t0, "a\x1b[31mred\x00\x07b\rc\tok"), wantLines: 1, wantText: "a�[31mred��b�c\tok"},
		{name: "C1 control and DEL", frame: dframe(0, t0, "x\u009b2Jy\x7fz"), wantLines: 1, wantText: "x�2Jy�z"},
		{name: "invalid UTF-8", frame: dframe(0, t0, "caf\xe9 \xff\xfe ok"), wantLines: 1, wantText: "caf� �� ok"},
		{name: "1 MB docker line (script cut bypassed)", frame: dframe(0, t0, mb), wantDropped: 1},
		{name: "1 MB journal line", frame: jframe(9, t0, "x.service", mb), wantDropped: 1},
		{name: "line over the text cap", frame: dframe(0, t0, strings.Repeat("é", TextCap)), wantLines: 1, wantText: strings.Repeat("é", TextCap/2), wantTrunc: true},
		{name: "line cut by the script", frame: "D 0 " + t0.Format(time.RFC3339Nano) + " " + strings.Repeat("b", dockerFrameCut-len(t0.Format(time.RFC3339Nano))-1), wantLines: 1, wantTrunc: true},
		{name: "journal field over 4 KiB is null", frame: fmt.Sprintf(`J {"__CURSOR":%q,"__REALTIME_TIMESTAMP":"%d","_SYSTEMD_UNIT":"a.service","MESSAGE":null}`, jcur(3), t0.UnixMicro()), wantLines: 1, wantText: "", wantTrunc: true},
		{name: "journal binary message", frame: fmt.Sprintf(`J {"__CURSOR":%q,"__REALTIME_TIMESTAMP":"%d","_SYSTEMD_UNIT":"a.service","MESSAGE":[104,105,255,27]}`, jcur(4), t0.UnixMicro()), wantLines: 1, wantText: "hi��"},
		{name: "journal cursor with shell metacharacters", frame: fmt.Sprintf(`J {"__CURSOR":"s=x';reboot;'","__REALTIME_TIMESTAMP":"%d","MESSAGE":"m"}`, t0.UnixMicro()), wantDropped: 1},
		{name: "journal not JSON", frame: "J {not json", wantDropped: 1},
		{name: "journal bad timestamp", frame: fmt.Sprintf(`J {"__CURSOR":%q,"__REALTIME_TIMESTAMP":"-5","MESSAGE":"m"}`, jcur(5)), wantDropped: 1},
		{name: "docker bad timestamp", frame: "D 0 yesterday hello", wantDropped: 1},
		{name: "docker unknown container index", frame: dframe(7, t0, "x"), wantDropped: 1},
		{name: "docker negative index", frame: dframe(-1, t0, "x"), wantDropped: 1},
		{name: "unknown frame kind", frame: "Z whatever", wantDropped: 1},
		{name: "container with a non-hex id", frame: "C 2 ../../etc web running", wantDropped: 1},
		{name: "container with a hostile name", frame: "C 2 " + strings.Repeat("c", 64) + " $(reboot) running", wantDropped: 1},
		{name: "unit with a glob", frame: "U *", wantDropped: 1},
		{name: "unit option injection", frame: "U --merge", wantDropped: 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// The hostile frame sits between two good ones of each source.
			out := output(
				jframe(1, t0, "a.service", "before"), tc.frame, jframe(2, t0.Add(time.Second), "a.service", "after"), "E J 0",
				dframe(0, t0, "before"), "E D 0 0", "E D 1 0",
			)
			c, err := Parse(out)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if c.Dropped != tc.wantDropped {
				t.Errorf("dropped = %d, want %d", c.Dropped, tc.wantDropped)
			}
			var got []Line
			for _, l := range c.Journal.Lines {
				if l.Text != "before" && l.Text != "after" {
					got = append(got, l)
				}
			}
			for _, r := range c.ContainerReads {
				for _, l := range r.Lines {
					if l.Text != "before" {
						got = append(got, l)
					}
				}
			}
			if len(c.Journal.Lines)-len(got) < 0 || !hasText(c.Journal.Lines, "before") || !hasText(c.Journal.Lines, "after") {
				t.Errorf("the hostile frame broke its neighbours: %+v", c.Journal.Lines)
			}
			if len(got) != tc.wantLines {
				t.Fatalf("got %d lines from the hostile frame, want %d: %+v", len(got), tc.wantLines, got)
			}
			for _, l := range got {
				if !utf8.ValidString(l.Text) || len(l.Text) > TextCap {
					t.Errorf("text not valid UTF-8 or over the cap (%d bytes)", len(l.Text))
				}
				if tc.wantText != "" || tc.wantLines > 0 && !tc.wantTrunc {
					if l.Text != tc.wantText {
						t.Errorf("text = %q, want %q", l.Text, tc.wantText)
					}
				}
				if l.Truncated != tc.wantTrunc {
					t.Errorf("truncated = %v, want %v", l.Truncated, tc.wantTrunc)
				}
			}
		})
	}
}

func hasText(lines []Line, s string) bool {
	for _, l := range lines {
		if l.Text == s {
			return true
		}
	}
	return false
}

// A source whose end marker never came (the script was cut off, or a
// hostile box stopped printing) is not Ended, and an unterminated last line
// is dropped rather than read as a whole line.
func TestParse_CutOffOutput(t *testing.T) {
	out := strings.TrimSuffix(output(jframe(1, t0, "a.service", "one"), "E J 0", dframe(0, t0, "partial line")), "\n")
	c, err := Parse(out)
	if err != nil {
		t.Fatal(err)
	}
	if !c.Journal.Ended {
		t.Error("journal should be ended")
	}
	if r := c.ContainerReads[0]; r != nil && (r.Ended || len(r.Lines) != 0) {
		t.Errorf("container 0 = %+v, want not ended and no lines", r)
	}
	if c.ContainerReads[1] != nil && c.ContainerReads[1].Ended {
		t.Error("container 1 never read, must not be ended")
	}
}

// The parser never reads past OutputCap, however much the box printed.
func TestParse_OutputCap(t *testing.T) {
	var b strings.Builder
	b.WriteString(output())
	line := dframe(0, t0, strings.Repeat("x", 1000)) + "\n"
	for b.Len() < OutputCap+(1<<20) {
		b.WriteString(line)
	}
	c, err := Parse(b.String())
	if err != nil {
		t.Fatal(err)
	}
	n := len(c.ContainerReads[0].Lines)
	if max := OutputCap / len(line); n > max {
		t.Errorf("parsed %d lines, more than fit in OutputCap (%d)", n, max)
	}
	if c.ContainerReads[0].Ended {
		t.Error("a capped read is not ended")
	}
}

func TestParse_Header(t *testing.T) {
	cases := []struct {
		name, out string
		wantErr   bool
		runtime   pb.BoxContainerRuntime
	}{
		{"empty", "", true, 0},
		{"no version", "N 1\nR docker\n", true, 0},
		{"future version", "V 2\nN 1\nR docker\n", true, 0},
		{"no clock", "V 1\nR docker\n", true, 0},
		{"bad clock", "V 1\nN soon\nR docker\n", true, 0},
		{"unknown runtime", "V 1\nN 1\nR lxd\n", true, 0},
		{"podman", "V 1\nN 1\nR podman\n", false, pb.BoxContainerRuntime_BOX_CONTAINER_RUNTIME_PODMAN},
		{"rootless", "V 1\nN 1\nR docker-rootless\n", false, pb.BoxContainerRuntime_BOX_CONTAINER_RUNTIME_DOCKER_ROOTLESS},
		{"none", "V 1\nN 1\nR none\nL 5 5\n", false, pb.BoxContainerRuntime_BOX_CONTAINER_RUNTIME_NONE},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, err := Parse(tc.out)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if err == nil && c.Runtime != tc.runtime {
				t.Errorf("runtime = %v, want %v", c.Runtime, tc.runtime)
			}
		})
	}
}

// FuzzParse: whatever the box prints, Parse neither panics nor returns a
// line that is invalid UTF-8 or over the text cap.
func FuzzParse(f *testing.F) {
	f.Add(output(jframe(1, t0, "a.service", "x"), "E J 0", dframe(0, t0, "y"), "E D 0 0"))
	f.Add("V 1\nN 1\nR docker\nD 0 \xff\xfe\n")
	f.Add("V 1\nN 1\nR docker\nC 0 " + testID0 + " w running\nD 0 2026-11-11T12:00:00Z \x1b\x00\n")
	f.Add("V 1\nN 1\nR none\nJ {\"MESSAGE\":[1,2,3]}\n")
	f.Fuzz(func(t *testing.T, out string) {
		c, err := Parse(out)
		if err != nil {
			return
		}
		check := func(l Line) {
			if !utf8.ValidString(l.Text) || len(l.Text) > TextCap || !utf8.ValidString(l.Source) {
				t.Fatalf("bad line %+v", l)
			}
		}
		for _, l := range c.Journal.Lines {
			check(l)
		}
		for _, r := range c.ContainerReads {
			for _, l := range r.Lines {
				check(l)
			}
		}
	})
}
