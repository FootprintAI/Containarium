package guardraildropin

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/footprintai/containarium/pkg/core/incus"
)

// newBuiltinChecker is a checker with the daemon's default flags: the
// built-in reference engine. Nothing is installed yet.
func newBuiltinChecker(t *testing.T) (*checker, *fakeBox) {
	t.Helper()
	box := newFakeBox()
	c, err := newChecker(box, Options{}.withDefaults(), bytesBinary(testBinary))
	if err != nil {
		t.Fatal(err)
	}
	c.clock = func() time.Time { return testNow }
	return c, box
}

func TestRenderEngineUnit(t *testing.T) {
	unit := string(RenderEngineUnit())
	for _, want := range []string{
		// Exec form: an absolute binary and its arguments, no shell.
		"ExecStart=" + HookBinaryPath + " guardrail engine serve --listen " + ReferenceEngineAddr + "\n",
		"Type=notify\n",
		"User=" + EngineUser + "\n",
		"Group=" + EngineGroup + "\n",
		"RuntimeDirectory=containarium-guardrail-reference\n",
		"RuntimeDirectoryMode=0750\n",
		"UMask=0117\n",
		"Restart=on-failure\n",
		"NoNewPrivileges=yes\n",
		// No network: the engine can open unix sockets and nothing else, so
		// it can never show up as traffic of the box.
		"RestrictAddressFamilies=AF_UNIX\n",
	} {
		if !strings.Contains(unit, want) {
			t.Errorf("unit lacks %q:\n%s", want, unit)
		}
	}
	for _, not := range []string{"User=root", "sh -c", "Timer", "OnCalendar", "AF_INET"} {
		if strings.Contains(unit, not) {
			t.Errorf("unit contains %q:\n%s", not, unit)
		}
	}
	// The daemon never installs under the name, or on the socket, of a
	// separately packaged engine.
	if ReferenceEngineUnit == operatorUnit || ReferenceEngineAddr == DefaultEngineAddr {
		t.Fatal("the built-in engine collides with the packaged engine's unit or socket")
	}
}

func TestEngineFlagCombinations(t *testing.T) {
	c, _ := newBuiltinChecker(t)
	if !strings.Contains(string(c.dropIn), `"`+ReferenceEngineAddr+`"`) {
		t.Fatalf("with the built-in engine the drop-in must name its socket:\n%s", c.dropIn)
	}
	for name, o := range map[string]Options{
		"built-in engine with another address":      {EngineAddr: "unix:///run/other/engine.sock"},
		"built-in engine with no address":           {EngineAddr: EngineNone},
		"the built-in unit's name as an operator's": {EngineUnit: ReferenceEngineUnit},
	} {
		if _, err := newChecker(newFakeBox(), o.withDefaults(), bytesBinary(testBinary)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	for name, o := range map[string]Options{
		"built-in engine, its own address spelled out": {EngineAddr: ReferenceEngineAddr},
		"operator unit, operator address":              {EngineUnit: operatorUnit, EngineAddr: "/run/x/engine.sock"},
		"no unit, no address":                          {EngineUnit: EngineNone, EngineAddr: EngineNone},
	} {
		if _, err := newChecker(newFakeBox(), o.withDefaults(), bytesBinary(testBinary)); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// Binary, accounts, unit, start, socket as the box user, and only then the
// drop-in. Removal is the reverse and leaves the group.
func TestBuiltinEngineInstallOrderAndRemoval(t *testing.T) {
	c, box := newBuiltinChecker(t)
	if err := c.install(testBox, testUser); err != nil {
		t.Fatal(err)
	}
	var steps []string
	for _, l := range box.log {
		f := strings.Fields(l)
		switch {
		case strings.HasPrefix(l, "write "), strings.HasPrefix(l, "mv "), strings.HasPrefix(l, "exec runuser"):
			steps = append(steps, f[0]+" "+f[len(f)-1])
		case strings.HasPrefix(l, "accounts "), strings.HasPrefix(l, "systemctl "):
			steps = append(steps, l)
		}
	}
	want := []string{
		"write " + tmpBinaryPath, "exec --help", "mv " + HookBinaryPath,
		"accounts " + EngineGroup + " " + EngineUser + " " + testUser,
		"write " + tmpUnitPath, "mv " + EngineUnitPath,
		"systemctl daemon-reload", "systemctl enable", "systemctl restart",
		"exec " + ReferenceEngineSocket,
		"write " + tmpDropInPath, "mv " + DropInPath,
	}
	if strings.Join(steps, ", ") != strings.Join(want, ", ") {
		t.Fatalf("install steps:\n got %v\nwant %v", steps, want)
	}
	if strings.HasSuffix(tmpUnitPath, ".service") {
		t.Fatal("the temporary unit must not be loadable as a unit")
	}
	if string(box.files[EngineUnitPath]) != string(RenderEngineUnit()) {
		t.Fatal("the installed unit is not the rendered one")
	}
	cur := mustCurrent(t, c)
	if got := c.check(testBox, testUser, cur); got.Coverage != covered {
		t.Fatalf("after install: %+v", got)
	}

	// The same install again rewrites no unit and restarts nothing.
	box.log = nil
	if err := c.install(testBox, testUser); err != nil {
		t.Fatal(err)
	}
	if w := box.logged("write "); len(w) != 1 || w[0] != "write "+tmpDropInPath {
		t.Fatalf("re-install wrote %v, want only the drop-in", w)
	}
	if got := strings.Join(box.logged("systemctl "), ", "); got != "systemctl enable, systemctl start" {
		t.Fatalf("re-install ran %q", got)
	}

	// Removal: drop-in first, then the unit, then the binary.
	box.log = nil
	if err := c.remove(testBox); err != nil {
		t.Fatal(err)
	}
	if len(box.files) != 0 || box.refRunning {
		t.Fatalf("left after remove: files %v, engine running %v", box.files, box.refRunning)
	}
	var order []string
	for _, l := range box.log {
		if strings.HasPrefix(l, "exec rm") || l == "remove-engine" {
			order = append(order, l)
		}
	}
	if got := strings.Join(order, ", "); got != "exec rm "+tmpDropInPath+", remove-engine, exec rm "+HookBinaryDir {
		t.Fatalf("removal order: %s", got)
	}
	if !box.inGroup {
		t.Fatal("removal took the box user out of the group; the group is left in place")
	}
}

// An engine that does not come up means no drop-in: with onFailure "block"
// and a hook that denies while the engine is not ready, a drop-in would
// block every tool call. That includes a drop-in from an earlier install.
func TestBuiltinEngineNotReadyLeavesNoDropIn(t *testing.T) {
	for name, breakIt := range map[string]func(*fakeBox){
		"the unit does not start": func(b *fakeBox) { b.engineStartFails = true; b.refRunning = false },
		"the box user cannot open the socket": func(b *fakeBox) {
			b.files[DropInPath] = []byte("an earlier drop-in")
			b.socketDenied = true
		},
	} {
		c, box := newBuiltinChecker(t)
		box.files[DropInPath] = []byte("an earlier drop-in")
		breakIt(box)
		err := c.install(testBox, testUser)
		if !errors.Is(err, errEngineNotReady) {
			t.Fatalf("%s: err = %v, want errEngineNotReady", name, err)
		}
		if box.has(DropInPath) || box.has(tmpDropInPath) {
			t.Fatalf("%s: a drop-in is in place without a ready engine", name)
		}
	}
}

// With an operator's unit the daemon installs none, and takes out one it
// installed under earlier flags.
func TestOperatorUnitInstallsNoEngine(t *testing.T) {
	box := newFakeBox()
	c, err := newChecker(box, operatorEngine.withDefaults(), bytesBinary(testBinary))
	if err != nil {
		t.Fatal(err)
	}
	box.files[EngineUnitPath] = RenderEngineUnit()
	box.refRunning = true
	if err := c.install(testBox, testUser); err != nil {
		t.Fatal(err)
	}
	if box.has(EngineUnitPath) || box.refRunning {
		t.Fatal("the unit of an earlier built-in configuration was left running")
	}
	if box.inGroup || len(box.logged("accounts ")) != 0 {
		t.Fatal("accounts were touched for an operator's engine")
	}
	for _, l := range box.logged("systemctl ") {
		if l != "systemctl is-active" {
			t.Fatalf("ran %q for an operator's engine", l)
		}
	}
	box.log = nil
	if err := c.install(testBox, testUser); err != nil {
		t.Fatal(err)
	}
	if len(box.logged("remove-engine")) != 0 {
		t.Fatal("removal ran again with nothing to remove")
	}
}

func TestCheckBuiltinEngine(t *testing.T) {
	tests := []struct {
		name   string
		setup  func(*fakeBox, *installed)
		want   Result
		detail string
	}{
		{"healthy", func(*fakeBox, *installed) {}, Result{Coverage: covered}, "in place"},
		{"unit stopped", func(b *fakeBox, _ *installed) { b.refRunning = false },
			Result{Coverage: engineDown, repair: true}, ReferenceEngineUnit + " is not active"},
		{"box user not in the group", func(b *fakeBox, _ *installed) { b.inGroup = false },
			Result{Coverage: engineDown, repair: true}, ReferenceEngineSocket},
		{"unit file changed", func(b *fakeBox, _ *installed) { b.files[EngineUnitPath] = []byte("[Service]\nExecStart=/bin/true\n") },
			Result{Coverage: tamperedC, repair: true}, "differs"},
		{"unit file replaced by a link", func(b *fakeBox, _ *installed) { b.meta[EngineUnitPath] = "symbolic link|0|777" },
			Result{Coverage: tamperedC, repair: true}, "regular"},
		{"unit file missing", func(b *fakeBox, _ *installed) { delete(b.files, EngineUnitPath) },
			Result{Coverage: notInstalledC, repair: true}, "missing"},
		{"unit from an earlier daemon version", func(b *fakeBox, prev *installed) {
			b.files[EngineUnitPath] = []byte("an earlier unit")
			prev.unit = sha256Hex([]byte("an earlier unit"))
		}, Result{repair: true, stale: true}, "earlier"},
		{"installed by a daemon that installed no unit", func(b *fakeBox, prev *installed) {
			delete(b.files, EngineUnitPath)
			prev.unit = ""
		}, Result{repair: true, stale: true}, "earlier"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c, box := newBuiltinChecker(t)
			if err := c.install(testBox, testUser); err != nil {
				t.Fatal(err)
			}
			prev := mustCurrent(t, c)
			tc.setup(box, &prev)
			got := c.check(testBox, testUser, prev)
			if got.Coverage != tc.want.Coverage || got.repair != tc.want.repair || got.stale != tc.want.stale || !strings.Contains(got.Detail, tc.detail) {
				t.Fatalf("got %+v", got)
			}
		})
	}
}

// The installed record round-trips, and a record written before there was
// a unit still parses.
func TestInstalledRecord(t *testing.T) {
	for _, in := range []installed{{binary: "b", dropIn: "d"}, {binary: "b", dropIn: "d", unit: "u"}} {
		if got := parseInstalled(in.String()); got != in {
			t.Errorf("round trip of %+v = %+v", in, got)
		}
	}
	if got := (installed{binary: "b", dropIn: "d"}).String(); got != "b:d" {
		t.Errorf("a record with no unit = %q, want the #3762 form", got)
	}
}

// Acceptance (#3767): with the default flags, enable on a box with no
// engine ends COVERED with the engine running; a stopped engine is reported
// and started again; disable removes the unit. None of it writes box config
// beyond the install record, so none of it is activity for auto-sleep.
func TestEnableWithBuiltinEngine(t *testing.T) {
	box := newFakeBox()
	inst := &fakeInstances{boxes: map[string]*incus.ContainerInfo{
		testBox: {Name: testBox, State: "Running", GuardrailHook: incus.GuardrailHookOff},
	}}
	m, err := newManager(inst, box, Options{}, bytesBinary(testBinary))
	if err != nil {
		t.Fatal(err)
	}
	m.checker.clock = func() time.Time { return testNow }

	got, err := m.SetEnabled(testUser, true)
	if err != nil {
		t.Fatal(err)
	}
	if got.Coverage != covered || !box.refRunning || !box.inGroup || !box.has(EngineUnitPath) {
		t.Fatalf("after enable: %+v, engine running %v, in group %v", got, box.refRunning, box.inGroup)
	}
	if rec := parseInstalled(inst.config[testBox]); rec.unit != sha256Hex(RenderEngineUnit()) {
		t.Fatalf("install record %q does not carry the unit", inst.config[testBox])
	}

	box.refRunning = false // the engine died and systemd gave up
	m.tick()
	if got, _ := m.Coverage(testUser); got.Coverage != engineDown {
		t.Fatalf("with the engine stopped: %+v", got)
	}
	m.tick()
	if got, _ := m.Coverage(testUser); got.Coverage != covered || !box.refRunning {
		t.Fatalf("the daemon did not start its engine again: %+v", got)
	}
	for _, w := range inst.writes {
		if !strings.Contains(w, incus.GuardrailHookKey) && !strings.Contains(w, incus.GuardrailHookInstalledKey) {
			t.Fatalf("a config write other than the switch and the install record: %v", inst.writes)
		}
	}

	if got, err = m.SetEnabled(testUser, false); err != nil || got.Coverage != featureOff {
		t.Fatalf("after disable: %+v, %v", got, err)
	}
	if box.fileCount() != 0 || box.refRunning {
		t.Fatalf("after disable: files %v, engine running %v", box.files, box.refRunning)
	}
}
