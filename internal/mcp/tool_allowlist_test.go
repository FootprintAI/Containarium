package mcp

import "testing"

func namesOf(tools []Tool) []string {
	out := make([]string, len(tools))
	for i, t := range tools {
		out[i] = t.Name
	}
	return out
}

func TestFilterToolsByAllowlist_ExactNames(t *testing.T) {
	tools := []Tool{{Name: "create_container"}, {Name: "list_containers"}, {Name: "delete_container"}}
	got, err := filterToolsByAllowlist(tools, "create_container,delete_container")
	if err != nil {
		t.Fatalf("filterToolsByAllowlist: %v", err)
	}
	want := []string{"create_container", "delete_container"}
	if got := namesOf(got); len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("got %v, want %v (registration order preserved)", got, want)
	}
}

func TestFilterToolsByAllowlist_PrefixGlob(t *testing.T) {
	tools := []Tool{
		{Name: "tracker_get_issue"}, {Name: "tracker_claim_issue"},
		{Name: "create_container"}, {Name: "list_containers"},
	}
	got, err := filterToolsByAllowlist(tools, "tracker_*")
	if err != nil {
		t.Fatalf("filterToolsByAllowlist: %v", err)
	}
	names := namesOf(got)
	if len(names) != 2 || names[0] != "tracker_get_issue" || names[1] != "tracker_claim_issue" {
		t.Fatalf("got %v, want exactly the two tracker_* tools, in order", names)
	}
}

func TestFilterToolsByAllowlist_MixedExactAndGlob(t *testing.T) {
	tools := []Tool{
		{Name: "tracker_get_issue"}, {Name: "tracker_claim_issue"}, {Name: "create_container"},
	}
	got, err := filterToolsByAllowlist(tools, "tracker_*, create_container")
	if err != nil {
		t.Fatalf("filterToolsByAllowlist: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("got %d tools, want 3", len(got))
	}
}

func TestFilterToolsByAllowlist_OverlappingEntriesDoNotDuplicate(t *testing.T) {
	tools := []Tool{{Name: "tracker_get_issue"}, {Name: "tracker_claim_issue"}}
	// "tracker_*" and the exact name both match tracker_get_issue.
	got, err := filterToolsByAllowlist(tools, "tracker_*,tracker_get_issue")
	if err != nil {
		t.Fatalf("filterToolsByAllowlist: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d tools, want exactly 2 (no duplicate for the double-matched tool)", len(got))
	}
}

func TestFilterToolsByAllowlist_UnknownEntry_FailsClosed(t *testing.T) {
	tools := []Tool{{Name: "create_container"}}
	_, err := filterToolsByAllowlist(tools, "create_container,does_not_exist")
	if err == nil {
		t.Fatal("an entry matching no tool must be an error, not a silent no-op")
	}
}

func TestFilterToolsByAllowlist_BlankEntriesIgnored(t *testing.T) {
	tools := []Tool{{Name: "create_container"}}
	got, err := filterToolsByAllowlist(tools, "create_container,, ,")
	if err != nil {
		t.Fatalf("filterToolsByAllowlist: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d tools, want 1", len(got))
	}
}

func TestFilterToolsByAllowlist_OnlyBlankEntries_Errors(t *testing.T) {
	tools := []Tool{{Name: "create_container"}}
	if _, err := filterToolsByAllowlist(tools, " , ,"); err == nil {
		t.Fatal("a pattern naming no tool at all must be an error")
	}
}

// TestNewServer_ToolAllowlist_Unset_RegistersEveryTool pins the default:
// Config.MCPTools empty leaves every tool available, unchanged from
// before the allow-list existed.
func TestNewServer_ToolAllowlist_Unset_RegistersEveryTool(t *testing.T) {
	all, err := NewServer(&Config{ServerURL: "http://localhost:8080", JWTToken: "t"})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	filtered, err := NewServer(&Config{ServerURL: "http://localhost:8080", JWTToken: "t", MCPTools: "create_container"})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	if len(filtered.tools) != 1 {
		t.Fatalf("filtered server has %d tools, want 1", len(filtered.tools))
	}
	if len(all.tools) == len(filtered.tools) {
		t.Fatalf("unset MCPTools should register every tool (%d), not match the filtered count (%d)", len(all.tools), len(filtered.tools))
	}
}

// TestNewServer_ToolAllowlist_UnknownEntry_FailsToStart pins the
// fail-closed startup behavior: an operator typo in CONTAINARIUM_MCP_TOOLS
// must not silently produce zero (or fewer) tools — it must refuse to
// start at all, since cmd/mcp-server's main.go calls log.Fatal on this
// error.
func TestNewServer_ToolAllowlist_UnknownEntry_FailsToStart(t *testing.T) {
	_, err := NewServer(&Config{ServerURL: "http://localhost:8080", JWTToken: "t", MCPTools: "does_not_exist"})
	if err == nil {
		t.Fatal("NewServer must fail when CONTAINARIUM_MCP_TOOLS names an unknown tool")
	}
}
