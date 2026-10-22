package cmd

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

func TestParseToolAccessLevel(t *testing.T) {
	cases := []struct {
		in      string
		want    pb.ToolAccessLevel
		wantErr bool
	}{
		{"none", pb.ToolAccessLevel_TOOL_ACCESS_LEVEL_NONE, false},
		{"build-tools", pb.ToolAccessLevel_TOOL_ACCESS_LEVEL_BUILD_TOOLS, false},
		{"full-sudo", pb.ToolAccessLevel_TOOL_ACCESS_LEVEL_FULL_SUDO, false},
		{"BUILD_TOOLS", pb.ToolAccessLevel_TOOL_ACCESS_LEVEL_BUILD_TOOLS, false},
		{"Full-Sudo", pb.ToolAccessLevel_TOOL_ACCESS_LEVEL_FULL_SUDO, false},
		{"", 0, true},
		{"install-packages", 0, true}, // removed by the revised proposal; must not parse
		{"root", 0, true},
		{"unspecified", 0, true},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			got, err := parseToolAccessLevel(tc.in)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if err == nil && got != tc.want {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
			if err != nil && !strings.Contains(err.Error(), "none, build-tools, full-sudo") {
				t.Errorf("error %q should list the valid levels", err)
			}
		})
	}
}

type fakeToolAccessAPI struct {
	level    pb.ToolAccessLevel
	setCalls []pb.ToolAccessLevel
	err      error
}

func (f *fakeToolAccessAPI) GetToolAccessLevel(string) (*pb.GetToolAccessLevelResponse, error) {
	return &pb.GetToolAccessLevelResponse{Level: f.level}, f.err
}

func (f *fakeToolAccessAPI) SetToolAccessLevel(_ string, l pb.ToolAccessLevel) (*pb.SetToolAccessLevelResponse, error) {
	if f.err != nil {
		return nil, f.err
	}
	f.setCalls = append(f.setCalls, l)
	f.level = l
	return &pb.SetToolAccessLevelResponse{Level: l}, nil
}

func TestRunToolAccessGet(t *testing.T) {
	cases := []struct {
		level pb.ToolAccessLevel
		want  string
	}{
		{pb.ToolAccessLevel_TOOL_ACCESS_LEVEL_UNSPECIFIED, "alice: none"}, // gateway omits zero enums
		{pb.ToolAccessLevel_TOOL_ACCESS_LEVEL_NONE, "alice: none"},
		{pb.ToolAccessLevel_TOOL_ACCESS_LEVEL_BUILD_TOOLS, "alice: build-tools"},
		{pb.ToolAccessLevel_TOOL_ACCESS_LEVEL_FULL_SUDO, "alice: full-sudo"},
	}
	for _, tc := range cases {
		var out bytes.Buffer
		if err := runToolAccessGet(&out, &fakeToolAccessAPI{level: tc.level}, "alice"); err != nil {
			t.Fatalf("%v: %v", tc.level, err)
		}
		if !strings.Contains(out.String(), tc.want) {
			t.Errorf("%v: output %q, want it to contain %q", tc.level, out.String(), tc.want)
		}
	}
}

func TestRunToolAccessSet(t *testing.T) {
	api := &fakeToolAccessAPI{}
	var out bytes.Buffer
	if err := runToolAccessSet(&out, api, "alice", "build-tools"); err != nil {
		t.Fatalf("set: %v", err)
	}
	if len(api.setCalls) != 1 || api.setCalls[0] != pb.ToolAccessLevel_TOOL_ACCESS_LEVEL_BUILD_TOOLS {
		t.Fatalf("set calls = %v", api.setCalls)
	}
	if !strings.Contains(out.String(), "alice") || !strings.Contains(out.String(), "build-tools") {
		t.Errorf("output %q should name the box and level", out.String())
	}
}

// The stored level is a record only in this slice; the output must say so
// rather than imply the box is now restricted or permitted.
func TestRunToolAccessSet_SaysNothingIsAppliedYet(t *testing.T) {
	var out bytes.Buffer
	if err := runToolAccessSet(&out, &fakeToolAccessAPI{}, "alice", "none"); err != nil {
		t.Fatalf("set: %v", err)
	}
	if !strings.Contains(out.String(), "not yet applied") {
		t.Errorf("output %q should state the level is recorded but not yet applied", out.String())
	}
}

func TestRunToolAccessSet_FullSudoWarns(t *testing.T) {
	var out bytes.Buffer
	if err := runToolAccessSet(&out, &fakeToolAccessAPI{}, "alice", "full-sudo"); err != nil {
		t.Fatalf("set: %v", err)
	}
	if !strings.Contains(out.String(), "unrestricted") {
		t.Errorf("full-sudo output %q should warn it is unrestricted", out.String())
	}
}

func TestRunToolAccessSet_InvalidLevelNeverCallsServer(t *testing.T) {
	api := &fakeToolAccessAPI{}
	err := runToolAccessSet(&bytes.Buffer{}, api, "alice", "install-packages")
	if err == nil {
		t.Fatal("expected an error for an unknown level")
	}
	if len(api.setCalls) != 0 {
		t.Fatalf("server was called with an invalid level: %v", api.setCalls)
	}
}

func TestRunToolAccess_PropagatesServerError(t *testing.T) {
	boom := errors.New("not authorized for this tenant")
	api := &fakeToolAccessAPI{err: boom}
	if err := runToolAccessGet(&bytes.Buffer{}, api, "alice"); !errors.Is(err, boom) {
		t.Errorf("get err = %v, want it to wrap %v", err, boom)
	}
	if err := runToolAccessSet(&bytes.Buffer{}, api, "alice", "none"); !errors.Is(err, boom) {
		t.Errorf("set err = %v, want it to wrap %v", err, boom)
	}
}
