package agentbox

import (
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// Tests focus on the pure-Go pieces — filesystem walk, slug
// derivation, compose-ps JSON parsing, arg helpers. The
// systemd-touching paths (enable / disable / linger) need a
// live user-systemd and are covered by the operator-side
// integration smoke documented in the runbook (Phase E).

// ----- discoverStacks ------------------------------------------------------

func TestDiscoverStacks_FindsAllComposeShapes(t *testing.T) {
	root := t.TempDir()
	mustMkdir(t, filepath.Join(root, "a"))
	mustMkdir(t, filepath.Join(root, "b"))
	mustMkdir(t, filepath.Join(root, "c"))
	mustMkdir(t, filepath.Join(root, "d"))
	mustWrite(t, filepath.Join(root, "a", "docker-compose.yml"), "")
	mustWrite(t, filepath.Join(root, "b", "docker-compose.yaml"), "")
	mustWrite(t, filepath.Join(root, "c", "compose.yml"), "")
	mustWrite(t, filepath.Join(root, "d", "compose.yaml"), "")

	stacks, err := discoverStacks(root, 5, nil)
	if err != nil {
		t.Fatalf("discoverStacks: %v", err)
	}
	if len(stacks) != 4 {
		t.Fatalf("got %d stacks, want 4: %+v", len(stacks), stacks)
	}
	// Output is sorted by ComposeDir; assert that ordering is
	// stable so the JSON we return to agents is reproducible.
	if !sort.SliceIsSorted(stacks, func(i, j int) bool {
		return stacks[i].ComposeDir < stacks[j].ComposeDir
	}) {
		t.Fatal("discoverStacks output not sorted")
	}
}

func TestDiscoverStacks_SkipsBuiltinDirs(t *testing.T) {
	root := t.TempDir()
	for _, junk := range []string{"node_modules", ".git", "vendor", "target", "dist", "__pycache__"} {
		mustMkdir(t, filepath.Join(root, junk, "deep"))
		mustWrite(t, filepath.Join(root, junk, "deep", "docker-compose.yml"), "")
	}
	mustMkdir(t, filepath.Join(root, "real-app"))
	mustWrite(t, filepath.Join(root, "real-app", "docker-compose.yml"), "")

	skip := map[string]struct{}{}
	for _, d := range defaultSkip {
		skip[d] = struct{}{}
	}
	stacks, err := discoverStacks(root, 5, skip)
	if err != nil {
		t.Fatalf("discoverStacks: %v", err)
	}
	if len(stacks) != 1 || filepath.Base(stacks[0].ComposeDir) != "real-app" {
		t.Fatalf("expected only real-app to survive skip; got %+v", stacks)
	}
}

func TestDiscoverStacks_NoSkipFindsEverything(t *testing.T) {
	root := t.TempDir()
	mustMkdir(t, filepath.Join(root, "node_modules"))
	mustWrite(t, filepath.Join(root, "node_modules", "docker-compose.yml"), "")
	mustMkdir(t, filepath.Join(root, "app"))
	mustWrite(t, filepath.Join(root, "app", "docker-compose.yml"), "")

	stacks, err := discoverStacks(root, 5, nil) // empty skip = walk everything
	if err != nil {
		t.Fatalf("discoverStacks: %v", err)
	}
	if len(stacks) != 2 {
		t.Fatalf("expected 2 stacks (including node_modules), got %d", len(stacks))
	}
}

func TestDiscoverStacks_HonorsMaxDepth(t *testing.T) {
	root := t.TempDir()
	// depth 3 below root: root/a/b/c/compose.yml
	deep := filepath.Join(root, "a", "b", "c")
	mustMkdir(t, deep)
	mustWrite(t, filepath.Join(deep, "compose.yml"), "")
	// depth 1: root/x/compose.yml
	mustMkdir(t, filepath.Join(root, "x"))
	mustWrite(t, filepath.Join(root, "x", "compose.yml"), "")

	// maxDepth=1 → only ./x should match.
	stacks, err := discoverStacks(root, 1, nil)
	if err != nil {
		t.Fatalf("discoverStacks: %v", err)
	}
	if len(stacks) != 1 || filepath.Base(stacks[0].ComposeDir) != "x" {
		t.Fatalf("maxDepth=1 should find only ./x; got %+v", stacks)
	}

	// maxDepth=5 → both.
	stacks, _ = discoverStacks(root, 5, nil)
	if len(stacks) != 2 {
		t.Fatalf("maxDepth=5 should find both; got %d", len(stacks))
	}
}

func TestDiscoverStacks_ComposeYmlBeatsDockerComposeYml(t *testing.T) {
	// Both file shapes in one dir — `compose.yml` is the
	// modern name and wins, matching docker compose v2's
	// own resolution order.
	root := t.TempDir()
	mustMkdir(t, filepath.Join(root, "p"))
	mustWrite(t, filepath.Join(root, "p", "docker-compose.yml"), "")
	mustWrite(t, filepath.Join(root, "p", "compose.yml"), "")

	stacks, _ := discoverStacks(root, 5, nil)
	if len(stacks) != 1 {
		t.Fatalf("expected 1 stack, got %d", len(stacks))
	}
	if filepath.Base(stacks[0].ComposeFile) != "compose.yml" {
		t.Errorf("expected compose.yml to win; got %s", stacks[0].ComposeFile)
	}
}

// ----- stackSlug / sanitizeSlug -------------------------------------------

func TestStackSlug_UsesTwoTailComponentsToReduceCollisions(t *testing.T) {
	cases := map[string]string{
		"/home/alice/deploy":              "alice-deploy",
		"/home/alice/Containarium/deploy": "containarium-deploy",
		"/home/bob/api":                   "bob-api",
		"/":                               "default",
		"":                                "default",
	}
	for in, want := range cases {
		got := stackSlug(in)
		if got != want {
			t.Errorf("stackSlug(%q) = %q; want %q", in, got, want)
		}
	}
}

func TestSanitizeSlug_RejectsSystemdUnsafeChars(t *testing.T) {
	cases := map[string]string{
		"plain":        "plain",
		"With Spaces":  "with-spaces",
		"under_score":  "under-score",
		"weird@chars!": "weird-chars",
		"---trim---":   "trim",
		"":             "default",
		"日本":           "default", // non-ASCII collapses to empty → fallback
		"v1.2.3":       "v1.2.3",  // dots preserved
	}
	for in, want := range cases {
		got := sanitizeSlug(in)
		if got != want {
			t.Errorf("sanitizeSlug(%q) = %q; want %q", in, got, want)
		}
	}
}

// ----- parseComposeJSON ---------------------------------------------------

func TestParseComposeJSON_ArrayShape(t *testing.T) {
	// docker compose v2 emits a JSON array.
	in := []byte(`[
		{"Name":"app","State":"running","Status":"Up 5 minutes"},
		{"Name":"db","State":"exited","Status":"Exited (0) 2 minutes ago"}
	]`)
	r, total, ok := parseComposeJSON(in)
	if !ok || total != 2 || r != 1 {
		t.Fatalf("got running=%d total=%d ok=%v", r, total, ok)
	}
}

func TestParseComposeJSON_NDJSONShape(t *testing.T) {
	// Some compose versions emit NDJSON instead.
	in := []byte("" +
		`{"Name":"a","State":"running"}` + "\n" +
		`{"Name":"b","State":"running"}` + "\n" +
		`{"Name":"c","Status":"Exited (137) 1 minute ago"}` + "\n")
	r, total, ok := parseComposeJSON(in)
	if !ok || total != 3 || r != 2 {
		t.Fatalf("got running=%d total=%d ok=%v", r, total, ok)
	}
}

func TestParseComposeJSON_EmptyAndGarbage(t *testing.T) {
	if _, _, ok := parseComposeJSON([]byte("")); ok {
		t.Error("empty input should not parse")
	}
	if _, _, ok := parseComposeJSON([]byte("not json at all")); ok {
		t.Error("garbage input should not parse")
	}
}

// ----- arg helpers --------------------------------------------------------

func TestArgInt_AcceptsFloat64AndInt(t *testing.T) {
	args := map[string]any{"f": float64(7), "i": 11, "i64": int64(13), "s": "nope"}
	if v, ok := argInt(args, "f"); !ok || v != 7 {
		t.Errorf("float64: got (%d, %v)", v, ok)
	}
	if v, ok := argInt(args, "i"); !ok || v != 11 {
		t.Errorf("int: got (%d, %v)", v, ok)
	}
	if v, ok := argInt(args, "i64"); !ok || v != 13 {
		t.Errorf("int64: got (%d, %v)", v, ok)
	}
	if _, ok := argInt(args, "s"); ok {
		t.Error("string should not parse as int")
	}
	if _, ok := argInt(args, "missing"); ok {
		t.Error("missing key should not parse")
	}
}

func TestArgStringSlice_FiltersNonStringAndEmpty(t *testing.T) {
	args := map[string]any{
		"good":        []any{"a", "b", "c"},
		"mixed":       []any{"a", 42, "", "b"},
		"missing-key": nil,
	}
	if got := argStringSlice(args, "good"); len(got) != 3 || got[2] != "c" {
		t.Errorf("good: got %v", got)
	}
	if got := argStringSlice(args, "mixed"); len(got) != 2 || got[1] != "b" {
		t.Errorf("mixed: got %v (expected non-strings + empty filtered)", got)
	}
	if got := argStringSlice(args, "missing"); got != nil {
		t.Errorf("missing key should return nil; got %v", got)
	}
}

// ----- expandUser ---------------------------------------------------------

func TestExpandUser(t *testing.T) {
	home := homeDir()
	cases := map[string]string{
		"~/foo":        filepath.Join(home, "foo"),
		"~":            home,
		"/abs":         "/abs",
		"rel":          "rel",
		"~unsupported": "~unsupported", // ~user form not supported; passes through
	}
	for in, want := range cases {
		if got := expandUser(in); got != want {
			t.Errorf("expandUser(%q) = %q; want %q", in, got, want)
		}
	}
}

// ----- helpers ------------------------------------------------------------

func mustMkdir(t *testing.T, p string) {
	t.Helper()
	if err := os.MkdirAll(p, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", p, err)
	}
}

func mustWrite(t *testing.T, p, content string) {
	t.Helper()
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", p, err)
	}
}
