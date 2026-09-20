package submit

import (
	"errors"
	"os"
	"strings"
	"testing"
)

// fakeBox is a BoxRunner test double. execFunc/readFunc are nil-checked
// so a test only needs to set the one it cares about.
type fakeBox struct {
	execFunc func(container string, command []string) (stdout, stderr string, err error)
	readFunc func(container, path string) ([]byte, error)

	execCalls []([]string)
	readCalls []string
}

func (f *fakeBox) ExecWithOutput(container string, command []string) (string, string, error) {
	f.execCalls = append(f.execCalls, command)
	if f.execFunc != nil {
		return f.execFunc(container, command)
	}
	return "", "", nil
}

func (f *fakeBox) ReadFile(container, path string) ([]byte, error) {
	f.readCalls = append(f.readCalls, path)
	if f.readFunc != nil {
		return f.readFunc(container, path)
	}
	return nil, nil
}

// validBundleBytes returns real bundle bytes (from an actual git repo)
// so tests exercising the "malformed" check have a genuinely valid
// bundle to contrast against, and the "happy path" test doesn't rely on
// a hand-rolled fixture that might not match real git's format.
func validBundleBytes(t *testing.T) []byte {
	t.Helper()
	dir := t.TempDir()
	testGit(t, dir, "init", "-q", "-b", "main")
	if err := os.WriteFile(dir+"/f.txt", []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	testGit(t, dir, "add", "f.txt")
	testGit(t, dir, "commit", "-q", "-m", "base")
	base := testGit(t, dir, "rev-parse", "HEAD")
	if err := os.WriteFile(dir+"/f.txt", []byte("y"), 0o644); err != nil {
		t.Fatal(err)
	}
	testGit(t, dir, "add", "f.txt")
	testGit(t, dir, "commit", "-q", "-m", "head")
	bundlePath := dir + "/out.bundle"
	testGit(t, dir, "bundle", "create", bundlePath, base+"..HEAD")
	b, err := os.ReadFile(bundlePath)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestBundle_Rejected(t *testing.T) {
	t.Run("box refuses an empty range", func(t *testing.T) {
		box := &fakeBox{execFunc: func(string, []string) (string, string, error) {
			return "", "fatal: Refusing to create empty bundle.", errors.New("exit status 128")
		}}
		_, err := ExtractBundle(box, "box1", "/workspace", "deadbeef", DefaultMaxBundleBytes)
		if err == nil {
			t.Fatal("want error, got nil")
		}
		if len(box.readCalls) != 0 {
			t.Errorf("ReadFile was called (%v); must not pull a bundle that failed to even build", box.readCalls)
		}
	})

	t.Run("over size cap is rejected without reading the file", func(t *testing.T) {
		box := &fakeBox{execFunc: func(_ string, cmd []string) (string, string, error) {
			script := strings.Join(cmd, " ")
			if strings.Contains(script, "wc -c") || strings.Contains(script, "stat") {
				return "999999999", "", nil
			}
			return "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef\n", "", nil
		}}
		_, err := ExtractBundle(box, "box1", "/workspace", "aaaa", 100)
		if !errors.Is(err, ErrBundleTooLarge) {
			t.Errorf("err = %v, want ErrBundleTooLarge", err)
		}
		if len(box.readCalls) != 0 {
			t.Errorf("ReadFile was called (%v); must reject on size before pulling the file", box.readCalls)
		}
	})

	t.Run("malformed content read back is rejected", func(t *testing.T) {
		box := &fakeBox{
			execFunc: func(_ string, cmd []string) (string, string, error) {
				script := strings.Join(cmd, " ")
				if strings.Contains(script, "wc -c") || strings.Contains(script, "stat") {
					return "7", "", nil
				}
				return "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef\n", "", nil
			},
			readFunc: func(string, string) ([]byte, error) {
				return []byte("garbage"), nil
			},
		}
		_, err := ExtractBundle(box, "box1", "/workspace", "aaaa", DefaultMaxBundleBytes)
		if !errors.Is(err, ErrBundleMalformed) {
			t.Errorf("err = %v, want ErrBundleMalformed", err)
		}
	})

	t.Run("box exec transport failure propagates", func(t *testing.T) {
		box := &fakeBox{execFunc: func(string, []string) (string, string, error) {
			return "", "", errors.New("box unreachable")
		}}
		_, err := ExtractBundle(box, "box1", "/workspace", "aaaa", DefaultMaxBundleBytes)
		if err == nil {
			t.Fatal("want error, got nil")
		}
		if len(box.readCalls) != 0 {
			t.Errorf("ReadFile was called (%v); must not proceed after exec failure", box.readCalls)
		}
	})
}

func TestExtractBundle_HappyPath(t *testing.T) {
	bundleBytes := validBundleBytes(t)
	headSHA := "cccccccccccccccccccccccccccccccccccccccc"

	box := &fakeBox{
		execFunc: func(_ string, cmd []string) (string, string, error) {
			script := strings.Join(cmd, " ")
			switch {
			case strings.Contains(script, "wc -c") || strings.Contains(script, "stat"):
				return "12345", "", nil
			case strings.Contains(script, "bundle create"):
				return headSHA + "\n", "", nil
			}
			t.Fatalf("unexpected exec: %v", cmd)
			return "", "", nil
		},
		readFunc: func(string, string) ([]byte, error) {
			return bundleBytes, nil
		},
	}

	result, err := ExtractBundle(box, "box1", "/workspace", "aaaa", DefaultMaxBundleBytes)
	if err != nil {
		t.Fatalf("ExtractBundle: %v", err)
	}
	if result.HeadSHA != headSHA {
		t.Errorf("HeadSHA = %q, want %q", result.HeadSHA, headSHA)
	}
	if result.BundlePath == "" {
		t.Fatal("BundlePath is empty")
	}
	defer func() { _ = os.Remove(result.BundlePath) }()

	info, err := os.Stat(result.BundlePath)
	if err != nil {
		t.Fatalf("stat bundle file: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("bundle file mode = %v, want 0600", info.Mode().Perm())
	}
	got, err := os.ReadFile(result.BundlePath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(bundleBytes) {
		t.Error("bundle file on disk does not match what ReadFile returned")
	}

	// The exec script must reference the workspace, the base commit, and
	// the literal ref HEAD (not a resolved sha) as the bundle range —
	// see PR #1951's flagged finding: `git bundle create` refuses a raw
	// sha..sha range with "Refusing to create empty bundle" even for a
	// non-empty commit range, because it has no ref to advertise.
	foundBundleCreate := false
	for _, call := range box.execCalls {
		script := strings.Join(call, " ")
		if strings.Contains(script, "bundle create") {
			foundBundleCreate = true
			if !strings.Contains(script, "aaaa..HEAD") {
				t.Errorf("bundle create script = %q, want it to use aaaa..HEAD (a ref upper bound)", script)
			}
			if !strings.Contains(script, "/workspace") {
				t.Errorf("bundle create script = %q, want it to reference the workspace path", script)
			}
		}
	}
	if !foundBundleCreate {
		t.Error("no exec call contained a bundle create")
	}
}

func TestExtractBundle_WorkspaceAndBaseAreShellQuoted(t *testing.T) {
	box := &fakeBox{execFunc: func(_ string, cmd []string) (string, string, error) {
		return "", "", errors.New("stop here, only checking argv shape")
	}}
	hostile := "/workspace'; rm -rf /; echo '"
	_, _ = ExtractBundle(box, "box1", hostile, "base'; touch pwned; echo '", DefaultMaxBundleBytes)
	if len(box.execCalls) == 0 {
		t.Fatal("no exec call made")
	}
	script := strings.Join(box.execCalls[0], " ")
	if strings.Contains(script, "rm -rf /") && !strings.Contains(script, "'\\''") {
		t.Errorf("hostile workspace path not shell-quoted: %q", script)
	}
}
