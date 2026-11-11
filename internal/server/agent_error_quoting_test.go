package server

import (
	"bytes"
	"context"
	"errors"
	"log"
	"strings"
	"testing"

	"github.com/footprintai/containarium/internal/agentengine"
)

// hostileName is a tenant-controlled value carrying a newline and an ESC.
const hostileName = "evil\nforged line\x1b[31m"

// assertOneCleanLogLine logs err with %v, the way callers do, and requires a
// single line holding no raw control byte (#3472).
func assertOneCleanLogLine(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("want an error, got nil")
	}
	var buf bytes.Buffer
	l := log.New(&buf, "", 0)
	l.Printf("run %q: %v", "run-1", err)
	line := strings.TrimSuffix(buf.String(), "\n")
	for _, r := range line {
		if r < 0x20 || r == 0x7f {
			t.Fatalf("log line holds raw control byte %q: %q", r, line)
		}
	}
}

func TestInBoxAgentErrors_QuoteTenantValues(t *testing.T) {
	runCases := map[string]*fakeInBox{
		"exec failure":      {execErr: errors.New("websocket closed")},
		"runtime missing":   {exitCode: exitCommandNotFound},
		"exit no artifact":  {exitCode: 1},
		"artifact read":     {readErr: errors.New("boom")},
		"unparseable":       {artifact: []byte("not json")},
		"artifact reported": {artifact: []byte(`{"error":"engine said no"}`)},
	}
	for name, box := range runCases {
		t.Run("run/"+name, func(t *testing.T) {
			s, _ := newSkillBoxHarness(t, newFakeRevocationStore())
			s.inBoxOps = box
			_, err := s.runInBoxAgentRun(hostileName, "/seed", "run-1", "skill", agentengine.Resolved{}, "")
			assertOneCleanLogLine(t, err)
		})
	}
	t.Run("run/no manager", func(t *testing.T) {
		_, err := (&AgentSkillServer{}).runInBoxAgentRun(hostileName, "/seed", "run-1", "skill", agentengine.Resolved{}, "")
		assertOneCleanLogLine(t, err)
	})

	serveCases := map[string]*serveBox{
		"launch exec failure": {launchErr: errors.New("instance not running")},
		"runtime missing":     {launchExit: exitCommandNotFound},
		"launch exit":         {launchExit: 3},
		"never ready":         {probeFailures: -1},
	}
	for name, box := range serveCases {
		t.Run("serve/"+name, func(t *testing.T) {
			err := serveServer(box).startServeMode(context.Background(), hostileName, "/seed", hostileName, agentengine.Resolved{}, "")
			assertOneCleanLogLine(t, err)
		})
	}
	t.Run("serve/context cancelled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		err := serveServer(&serveBox{probeFailures: -1}).startServeMode(ctx, hostileName, "/seed", hostileName, agentengine.Resolved{}, "")
		assertOneCleanLogLine(t, err)
	})
	t.Run("serve/no manager", func(t *testing.T) {
		err := (&AgentSkillServer{}).startServeMode(context.Background(), hostileName, "/seed", hostileName, agentengine.Resolved{}, "")
		assertOneCleanLogLine(t, err)
	})
}
