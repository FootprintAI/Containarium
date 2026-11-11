package boxlogs

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// The script's output is one frame per line:
//
//	V 1                          format version (first line)
//	N <unix nanoseconds>         the box's clock when reading started
//	R <runtime>                  docker | none | podman | docker-rootless
//	U <unit>                     a loaded service unit (filter names)
//	C <idx> <id> <name> <state>  a container, idx counting from 0
//	L <journal> <container>      the per-source line caps the script applied
//	J <journalctl -o json line>  one journal entry
//	E J <rc>                     end of the journal read, reader's exit code
//	D <idx> <RFC3339Nano> <text> one container line
//	E D <idx> <rc>               end of container idx's read
//
// A frame that does not match its grammar exactly is skipped and counted.

var (
	unitPattern          = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9@_.:-]{0,127}$`)
	containerNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)
	containerIDPattern   = regexp.MustCompile(`^[0-9a-f]{64}$`)
	containerStates      = map[string]bool{"created": true, "running": true, "paused": true, "restarting": true, "removing": true, "exited": true, "dead": true}
	runtimes             = map[string]pb.BoxContainerRuntime{
		"none":            pb.BoxContainerRuntime_BOX_CONTAINER_RUNTIME_NONE,
		"docker":          pb.BoxContainerRuntime_BOX_CONTAINER_RUNTIME_DOCKER,
		"podman":          pb.BoxContainerRuntime_BOX_CONTAINER_RUNTIME_PODMAN,
		"docker-rootless": pb.BoxContainerRuntime_BOX_CONTAINER_RUNTIME_DOCKER_ROOTLESS,
	}
)

// Container is one container the script listed.
type Container struct {
	Index int
	ID    string
	Name  string
	State string
}

// SourceRead is what one source's reader printed.
type SourceRead struct {
	Lines []Line
	// Ended is set when the source's end marker arrived: the read was not
	// cut off by the output cap.
	Ended bool
	// RC is the reader's exit code from the end marker: 0 done, 141 stopped
	// by the line cap, 124/137 timed out.
	RC int
}

// complete reports whether the reader ran to its end: its end marker
// arrived and it did not time out. It may still have stopped at the line cap.
func (r *SourceRead) complete() bool {
	return r != nil && r.Ended && r.RC != 124 && r.RC != 137
}

// Collection is one parsed script run.
type Collection struct {
	Now     time.Time
	Runtime pb.BoxContainerRuntime
	// Units are the loaded service units, the valid unit filter names.
	Units      []string
	Containers []Container
	// JournalLimit and ContainerLimit are the per-source line caps the
	// script applied.
	JournalLimit, ContainerLimit int
	Journal                      SourceRead
	// ContainerReads holds each read container's lines, by index.
	ContainerReads map[int]*SourceRead
	// Dropped counts frames that did not parse.
	Dropped int
}

func (c *Collection) container(idx int) *Container {
	for i := range c.Containers {
		if c.Containers[i].Index == idx {
			return &c.Containers[i]
		}
	}
	return nil
}

// Parse reads the script's output. Only a missing or unknown header is an
// error; any other frame that does not parse is skipped and counted. At most
// OutputCap bytes are read, and a last line with no newline is incomplete
// and skipped.
func Parse(out string) (*Collection, error) {
	if len(out) > OutputCap {
		out = out[:OutputCap]
	}
	c := &Collection{ContainerReads: map[int]*SourceRead{}}
	var haveV, haveN, haveR bool
	for len(out) > 0 {
		i := strings.IndexByte(out, '\n')
		if i < 0 {
			c.Dropped++ // unterminated: cut off mid-line
			break
		}
		line := out[:i]
		out = out[i+1:]
		if len(line) > MaxFrameLine {
			c.Dropped++
			continue
		}
		kind, rest, _ := strings.Cut(line, " ")
		switch {
		case !haveV:
			if line != "V 1" {
				return nil, fmt.Errorf("box logs output: unknown format %q", truncateForError(line))
			}
			haveV = true
		case kind == "N" && !haveN:
			ns, err := strconv.ParseInt(rest, 10, 64)
			if err != nil || ns <= 0 {
				return nil, fmt.Errorf("box logs output: bad clock %q", truncateForError(rest))
			}
			c.Now, haveN = time.Unix(0, ns).UTC(), true
		case kind == "R" && !haveR:
			rt, ok := runtimes[rest]
			if !ok {
				return nil, fmt.Errorf("box logs output: unknown runtime %q", truncateForError(rest))
			}
			c.Runtime, haveR = rt, true
		case !haveN || !haveR:
			return nil, errors.New("box logs output: frames before the clock and runtime")
		default:
			if !c.frame(kind, rest) {
				c.Dropped++
			}
		}
	}
	if !haveV || !haveN || !haveR {
		return nil, errors.New("box logs output: incomplete header")
	}
	return c, nil
}

// frame applies one body frame; false means it did not parse.
func (c *Collection) frame(kind, rest string) bool {
	switch kind {
	case "U":
		if !unitPattern.MatchString(rest) || len(c.Units) >= 512 {
			return false
		}
		c.Units = append(c.Units, rest)
	case "C":
		f := strings.Split(rest, " ")
		if len(f) != 4 || len(c.Containers) >= MaxContainers {
			return false
		}
		idx, err := strconv.Atoi(f[0])
		if err != nil || idx < 0 || idx >= MaxContainers || c.container(idx) != nil ||
			!containerIDPattern.MatchString(f[1]) || !containerNamePattern.MatchString(f[2]) || !containerStates[f[3]] {
			return false
		}
		c.Containers = append(c.Containers, Container{Index: idx, ID: f[1], Name: f[2], State: f[3]})
	case "L":
		f := strings.Split(rest, " ")
		if len(f) != 2 {
			return false
		}
		j, err1 := strconv.Atoi(f[0])
		d, err2 := strconv.Atoi(f[1])
		if err1 != nil || err2 != nil || j < 0 || d < 0 {
			return false
		}
		c.JournalLimit, c.ContainerLimit = j, d
	case "J":
		if c.Journal.Ended {
			return false
		}
		l, ok := parseJournal(rest)
		if !ok {
			return false
		}
		c.Journal.Lines = append(c.Journal.Lines, l)
	case "D":
		idxS, rest, _ := strings.Cut(rest, " ")
		r, ct := c.read(idxS)
		if r == nil || r.Ended {
			return false
		}
		l, ok := parseDocker(rest)
		if !ok {
			return false
		}
		l.Source, l.containerID = ct.Name, ct.ID
		r.Lines = append(r.Lines, l)
	case "E":
		f := strings.Split(rest, " ")
		switch {
		case len(f) == 2 && f[0] == "J":
			rc, err := strconv.Atoi(f[1])
			if err != nil || c.Journal.Ended {
				return false
			}
			c.Journal.Ended, c.Journal.RC = true, rc
		case len(f) == 3 && f[0] == "D":
			r, _ := c.read(f[1])
			rc, err := strconv.Atoi(f[2])
			if r == nil || err != nil || r.Ended {
				return false
			}
			r.Ended, r.RC = true, rc
		default:
			return false
		}
	default:
		return false
	}
	return true
}

// read returns the read of the listed container with index idxS.
func (c *Collection) read(idxS string) (*SourceRead, *Container) {
	idx, err := strconv.Atoi(idxS)
	if err != nil {
		return nil, nil
	}
	ct := c.container(idx)
	if ct == nil {
		return nil, nil
	}
	r := c.ContainerReads[idx]
	if r == nil {
		r = &SourceRead{}
		c.ContainerReads[idx] = r
	}
	return r, ct
}

// journalEntry is the part of a `journalctl -o json` entry the reader uses.
// A field journald could not print as text is an array of byte values, and
// one over 4096 bytes is null.
type journalEntry struct {
	Cursor   string          `json:"__CURSOR"`
	Realtime string          `json:"__REALTIME_TIMESTAMP"`
	Unit     json.RawMessage `json:"_SYSTEMD_UNIT"`
	Ident    json.RawMessage `json:"SYSLOG_IDENTIFIER"`
	Message  json.RawMessage `json:"MESSAGE"`
}

func parseJournal(s string) (Line, bool) {
	var e journalEntry
	if err := json.Unmarshal([]byte(s), &e); err != nil || !ValidJournalCursor(e.Cursor) {
		return Line{}, false
	}
	us, err := strconv.ParseInt(e.Realtime, 10, 64)
	if err != nil || us <= 0 {
		return Line{}, false
	}
	msg, present := journalField(e.Message)
	text, truncated := Sanitize(msg)
	l := Line{
		Time:          time.UnixMicro(us).UTC(),
		Kind:          pb.BoxLogSourceKind_BOX_LOG_SOURCE_KIND_JOURNAL,
		Text:          text,
		Truncated:     truncated || !present,
		journalCursor: e.Cursor,
	}
	if u, _ := journalField(e.Unit); unitPattern.Match(u) {
		l.Source = string(u)
	} else if id, _ := journalField(e.Ident); len(id) > 0 {
		l.Source, _ = Sanitize(id[:min(len(id), 128)])
	} else {
		l.Source = "journal"
	}
	return l, true
}

// journalField decodes a journal JSON field: a string, an array of byte
// values, or null/absent (present=false).
func journalField(raw json.RawMessage) (b []byte, present bool) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, false
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return []byte(s), true
	}
	var bs []byte // from a JSON array of numbers 0..255
	if raw[0] == '[' && json.Unmarshal(raw, &bs) == nil {
		return bs, true
	}
	return nil, false
}

func parseDocker(s string) (Line, bool) {
	ts, text, _ := strings.Cut(s, " ")
	t, err := time.Parse(time.RFC3339Nano, ts)
	if err != nil {
		return Line{}, false
	}
	out, truncated := Sanitize([]byte(text))
	return Line{
		Time:      t.UTC(),
		Kind:      pb.BoxLogSourceKind_BOX_LOG_SOURCE_KIND_CONTAINER,
		Text:      out,
		Truncated: truncated || len(s) >= dockerFrameCut,
	}, true
}

// Sanitize turns raw log bytes into display-safe text: invalid UTF-8 and
// control characters other than tab (C0, DEL, C1) become U+FFFD, and the
// result is capped at TextCap bytes on a rune boundary.
func Sanitize(b []byte) (string, bool) {
	var sb strings.Builder
	sb.Grow(min(len(b), TextCap))
	for len(b) > 0 {
		r, size := utf8.DecodeRune(b)
		b = b[size:]
		if r != '\t' && (r < 0x20 || (r >= 0x7f && r <= 0x9f)) {
			r = utf8.RuneError
		}
		if sb.Len()+utf8.RuneLen(r) > TextCap {
			return sb.String(), true
		}
		sb.WriteRune(r)
	}
	return sb.String(), false
}

func truncateForError(s string) string {
	if len(s) > 64 {
		s = s[:64]
	}
	return strings.ToValidUTF8(s, "?")
}

func lineProto(l Line) *pb.BoxLogLine {
	return &pb.BoxLogLine{
		Time:       timestamppb.New(l.Time),
		SourceKind: l.Kind,
		Source:     l.Source,
		Text:       l.Text,
		Truncated:  l.Truncated,
	}
}
