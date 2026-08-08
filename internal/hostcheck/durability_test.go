package hostcheck

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestIsOwnMount distinguishes a path that is its own mount point from a
// plain directory sitting on some ancestor's filesystem.
//
// This is the durability test for #1154. `os.Stat` cannot tell the two
// apart — the directory exists either way — which is how the daemon came
// to write a recovery config onto the boot disk and report success. The
// file exists only to survive instance recreation, so writing it
// somewhere that dies with the instance is worse than not writing it: an
// operator finds a current, well-formed recovery config with a recent
// mtime and reasonably concludes recovery is covered.
func TestIsOwnMount(t *testing.T) {
	for _, tc := range []struct {
		name    string
		mounts  string
		target  string
		want    bool
		wantErr bool
	}{
		{
			name:   "persistent disk mounted at the target",
			mounts: "/dev/sda1 / ext4 rw 0 0\n/dev/sdb1 /mnt/incus-data ext4 rw 0 0\n",
			target: "/mnt/incus-data",
			want:   true,
		},
		{
			name:   "plain directory on the boot disk",
			mounts: "/dev/sda1 / ext4 rw 0 0\n",
			target: "/mnt/incus-data",
			want:   false,
		},
		{
			name: "nested mount does not count as the target's own",
			// A disk mounted *below* the target does not make the
			// target durable.
			mounts: "/dev/sda1 / ext4 rw 0 0\n/dev/sdb1 /mnt/incus-data/sub ext4 rw 0 0\n",
			target: "/mnt/incus-data",
			want:   false,
		},
		{
			name:   "trailing slash on the target is not a different path",
			mounts: "/dev/sda1 / ext4 rw 0 0\n/dev/sdb1 /mnt/incus-data ext4 rw 0 0\n",
			target: "/mnt/incus-data/",
			want:   true,
		},
		{
			name: "longest prefix wins",
			// With both / and /mnt mounted, a naive first match picks
			// "/" and would call the target durable when it is not.
			mounts: "/dev/sda1 / ext4 rw 0 0\n/dev/sdb1 /mnt ext4 rw 0 0\n",
			target: "/mnt/incus-data",
			want:   false,
		},
		{
			name:   "pseudo-filesystems are ignored",
			mounts: "tmpfs /mnt/incus-data tmpfs rw 0 0\n/dev/sda1 / ext4 rw 0 0\n",
			target: "/mnt/incus-data",
			// tmpfs is not a /dev/ device, so the covering real
			// filesystem is "/" — and a tmpfs would not be durable
			// anyway.
			want: false,
		},
		{
			name:    "unreadable mounts is an error, not a false verdict",
			mounts:  "",
			target:  "/mnt/incus-data",
			wantErr: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "mounts")
			if !tc.wantErr {
				write(t, path, tc.mounts)
			}

			got, err := isOwnMount(path, tc.target)
			if tc.wantErr {
				if err == nil {
					t.Fatal("want an error when /proc/mounts cannot be read — reporting " +
						"'not durable' on a read failure would be a guess presented as a fact")
				}
				return
			}
			if err != nil {
				t.Fatalf("isOwnMount: %v", err)
			}
			if got != tc.want {
				t.Errorf("isOwnMount(%q) = %v, want %v\nmounts:\n%s", tc.target, got, tc.want, tc.mounts)
			}
		})
	}
}

// The recovery-config check must surface in `containarium doctor`, not
// only in a log line an operator will miss. A recovery config on the
// boot disk is discovered during a recovery otherwise — the worst
// possible moment.
func TestRecoveryConfigDurableCheck(t *testing.T) {
	t.Run("durable when the path is its own mount", func(t *testing.T) {
		p, dir := tempPaths(t)
		write(t, p.procMounts, "/dev/sda1 / ext4 rw 0 0\n/dev/sdb1 "+dir+" ext4 rw 0 0\n")
		p.recoveryDir = dir

		c := recoveryConfigDurableCheck(p)
		if !c.OK {
			t.Errorf("want OK, got %+v", c)
		}
	})

	t.Run("not durable when it is a boot-disk directory", func(t *testing.T) {
		p, dir := tempPaths(t)
		write(t, p.procMounts, "/dev/sda1 / ext4 rw 0 0\n")
		p.recoveryDir = dir

		c := recoveryConfigDurableCheck(p)
		if c.OK {
			t.Error("a plain directory on the boot disk was reported as durable — this is the #1154 bug")
		}
		if c.Detail == "" {
			t.Error("a failing check must explain itself")
		}
	})

	t.Run("absent directory does not claim a pass", func(t *testing.T) {
		p, _ := tempPaths(t)
		write(t, p.procMounts, "/dev/sda1 / ext4 rw 0 0\n")
		p.recoveryDir = filepath.Join(t.TempDir(), "does-not-exist")

		c := recoveryConfigDurableCheck(p)
		// A host with no persistent storage writes no recovery config
		// and cannot be rebuilt after instance recreation. That is a
		// real finding, not a pass — and the posture contract
		// (TestRunPosture_UnknownHostReportsNoPasses) forbids claiming
		// OK without positive evidence either way.
		if c.OK {
			t.Error("reported OK for a host with no persistent storage: nothing was verified")
		}
		if !strings.Contains(c.Detail, "instance recreation") {
			t.Errorf("detail should say what the operator loses, got %q", c.Detail)
		}
	})
}
