package server

import "testing"

// #3397: an allowed `git fetch` / `git clone` must not run a program chosen by
// its arguments. Ordinary fetches and clones keep working at every level.
func TestBoxRunPolicy_GitFetchCloneOptionExecution(t *testing.T) {
	for _, level := range []string{"none", "build_tools", "full_sudo"} {
		p, err := boxRunPolicyFor(level)
		if err != nil {
			t.Fatal(err)
		}
		for _, tc := range []struct {
			cmd  string
			want bool
		}{
			// still allowed
			{"git fetch", true},
			{"git fetch origin", true},
			{"git fetch origin main", true},
			{"git fetch --all --prune", true},
			{"git fetch --unshallow", true},
			{"git fetch -u origin", true},
			{"git fetch --depth 1 origin main", true},
			{"git fetch --recurse-submodules origin", true},
			{"git clone https://example.com/o/r.git work", true},
			{"git clone https://example.com/o/r.git", true},
			{"git clone --depth 1 https://example.com/o/r.git work", true},
			{"git clone -q https://example.com/o/r.git work", true},
			{"git clone -b main https://example.com/o/r.git work", true},
			{"git clone --recurse-submodules https://example.com/o/r.git work", true},
			{"git clone https://example.com/o/my-cache.git work", true},
			{"git -C /r fetch origin", true},
			{"git -C /r clone https://example.com/o/r.git d", true},
			// refused: fetch
			{"git fetch --upload-pack=evil origin", false},
			{"git fetch --upload-pack evil origin", false},
			{"git fetch origin --upload-pack=evil", false},
			{"git fetch --upl=evil origin", false},
			{"git fetch --receive-pack=evil origin", false},
			{"git fetch --config=a.b=c origin", false},
			{"git fetch --config-env=a.b=C origin", false},
			{"git fetch origin --config-env=a.b=C", false},
			// refused: clone
			{"git clone --upload-pack=evil u d", false},
			{"git clone --upload-pack evil u d", false},
			{"git clone u d --upload-pack=evil", false},
			{"git clone --u=evil u d", false},
			{"git clone -u evil u d", false},
			{"git clone -uevil u d", false},
			{"git clone u d -u evil", false},
			{"git clone -qu evil u d", false},
			{"git clone -su evil u d", false},
			{"git clone --receive-pack=evil u d", false},
			{"git clone -c core.sshCommand=evil u d", false},
			{"git clone -ccore.sshCommand=evil u d", false},
			{"git clone u d -c core.sshCommand=evil", false},
			{"git clone -qc core.sshCommand=evil u d", false},
			{"git clone --config core.sshCommand=evil u d", false},
			{"git clone --config=core.sshCommand=evil u d", false},
			{"git clone --config-env=core.sshCommand=E u d", false},
			{"git clone --conf core.sshCommand=evil u d", false},
			{"git clone --template=/tmp/t u d", false},
			{"git clone --template /tmp/t u d", false},
			{"git clone u d --template=/tmp/t", false},
			{"git clone --tem=/tmp/t u d", false},
			// refused: after a leading global option
			{"git -C /r fetch origin --upload-pack=evil", false},
			{"git -C /r clone -u evil u d", false},
			{"git -C /r clone -qu evil u d", false},
			{"git -C /r clone -ccore.x=y u d", false},
			{"git -C /r clone --template=/t u d", false},
			{"git --git-dir=/r/.git fetch --config=a.b=c origin", false},
			{"git --work-tree=/r clone --template=/t u d", false},
		} {
			if got := bashDecision(p, tc.cmd); got != tc.want {
				t.Errorf("%s: %q allowed = %v, want %v", level, tc.cmd, got, tc.want)
			}
		}
	}
}
