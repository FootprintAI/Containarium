package autosleep

import (
	"strings"
	"testing"
	"time"
)

// TestDecide_TableDriven covers each of Decide's rules in order. Each
// case is a one-line statement of the rule it locks down so a future
// reader can find the rule by grepping the want.action / want.reason.
func TestDecide_TableDriven(t *testing.T) {
	now := time.Date(2026, 5, 18, 12, 0, 0, 0, time.UTC)
	mkInput := func() DecideInput {
		return DecideInput{
			Username:             "alice",
			State:                "Running",
			AutoSleepEnabled:     true,
			IdleThresholdMinutes: 15,
			IsCoreRole:           false,
			LastStartedAt:        now.Add(-2 * time.Hour),
			LastNetworkActivity:  now.Add(-5 * time.Minute),
			Now:                  now,
		}
	}

	tests := []struct {
		name        string
		mutate      func(*DecideInput)
		wantAction  DecideAction
		wantReason  string // substring match
		wantIdleGTE int    // 0 disables check; sleep cases set this
	}{
		{
			name:       "rule1_disabled",
			mutate:     func(in *DecideInput) { in.AutoSleepEnabled = false },
			wantAction: ActionNothing,
			wantReason: "not enabled",
		},
		{
			name:       "rule2_core_role_never_sleeps",
			mutate:     func(in *DecideInput) { in.IsCoreRole = true },
			wantAction: ActionNothing,
			wantReason: "core container",
		},
		{
			name:       "rule3_stopped_container_skipped",
			mutate:     func(in *DecideInput) { in.State = "Stopped" },
			wantAction: ActionNothing,
			wantReason: "Stopped",
		},
		{
			name: "rule4_anti_thrash_recently_started",
			mutate: func(in *DecideInput) {
				// 5m after start, threshold=15m; 2× threshold = 30m window.
				in.LastStartedAt = now.Add(-5 * time.Minute)
				in.LastNetworkActivity = now.Add(-1 * time.Hour) // idle is huge, but the window protects us.
			},
			wantAction: ActionNothing,
			wantReason: "recently started",
		},
		{
			name: "rule5_no_network_signal_no_start_undecidable",
			mutate: func(in *DecideInput) {
				in.LastStartedAt = time.Time{}
				in.LastNetworkActivity = time.Time{}
			},
			wantAction: ActionNothing,
			wantReason: "no traffic signal",
		},
		{
			name: "rule5_no_network_signal_with_start_above_threshold",
			mutate: func(in *DecideInput) {
				in.LastNetworkActivity = time.Time{}
				in.LastStartedAt = now.Add(-45 * time.Minute) // outside the 30m anti-thrash, 45m idle
			},
			wantAction:  ActionSleep,
			wantReason:  "no network signal",
			wantIdleGTE: 45,
		},
		{
			name: "rule6_idle_below_threshold",
			mutate: func(in *DecideInput) {
				in.LastNetworkActivity = now.Add(-5 * time.Minute) // 5m < 15m
			},
			wantAction: ActionNothing,
			wantReason: "below threshold",
		},
		{
			name: "rule6_idle_at_threshold_sleeps",
			mutate: func(in *DecideInput) {
				in.LastNetworkActivity = now.Add(-15 * time.Minute) // exactly threshold
			},
			wantAction:  ActionSleep,
			wantReason:  "idle 15m >= threshold 15m",
			wantIdleGTE: 15,
		},
		{
			name: "rule6_idle_well_above_threshold_sleeps",
			mutate: func(in *DecideInput) {
				in.LastNetworkActivity = now.Add(-90 * time.Minute)
			},
			wantAction:  ActionSleep,
			wantReason:  "idle 90m >= threshold 15m",
			wantIdleGTE: 90,
		},
		{
			name: "rule4_just_past_window_idle_still_protects",
			mutate: func(in *DecideInput) {
				// 31m after start, threshold=15m; outside the 30m anti-thrash by 1m.
				in.LastStartedAt = now.Add(-31 * time.Minute)
				in.LastNetworkActivity = now.Add(-31 * time.Minute) // idle 31m
			},
			wantAction:  ActionSleep,
			wantReason:  "idle 31m",
			wantIdleGTE: 31,
		},
		// --- edge cases below ---
		//
		// Threshold=0 is degenerate. Today the impl computes
		// 2*0*time.Minute == 0 for the anti-thrash window so the
		// recently-started gate never fires; idle (any positive value)
		// is then >= 0 → sleep. This codifies current behavior but is
		// flagged as a likely-pathological input the Toggle handler
		// already clamps away from (see TestToggleAutoSleep_NegativeThreshold...).
		{
			name: "edge_threshold_zero_sleeps_immediately",
			mutate: func(in *DecideInput) {
				in.IdleThresholdMinutes = 0
				in.LastNetworkActivity = now.Add(-1 * time.Minute) // 1m idle, threshold 0
			},
			wantAction: ActionSleep,
			wantReason: "idle 1m >= threshold 0m",
		},
		// LastNetworkActivity in the future implies clock skew; idle
		// minutes are negative, which is < threshold, so we do nothing.
		{
			name: "edge_network_activity_in_future_clock_skew",
			mutate: func(in *DecideInput) {
				in.LastNetworkActivity = now.Add(10 * time.Minute)
			},
			wantAction: ActionNothing,
			wantReason: "below threshold",
		},
		// LastStartedAt in the future also implies clock skew; the
		// anti-thrash window evaluates "sinceStart < 2*threshold" as
		// true (a negative duration is < any positive duration), so
		// the rule fires and we leave the container alone.
		{
			name: "edge_last_started_in_future_clock_skew",
			mutate: func(in *DecideInput) {
				in.LastStartedAt = now.Add(10 * time.Minute)
				in.LastNetworkActivity = now.Add(-90 * time.Minute) // would otherwise sleep
			},
			wantAction: ActionNothing,
			wantReason: "recently started",
		},
		// Both signals zero → rule 5 falls through to "undecidable",
		// not "idle forever". This is the safer default — a fresh
		// container with no traffic record shouldn't be sleep-bombed
		// the moment the ticker first sees it.
		{
			name: "edge_both_signals_zero_undecidable",
			mutate: func(in *DecideInput) {
				in.LastStartedAt = time.Time{}
				in.LastNetworkActivity = time.Time{}
			},
			wantAction: ActionNothing,
			wantReason: "no traffic signal and no last-start",
		},
		// Idle exactly equal to threshold sleeps — comparison is >=,
		// not >. Locks the boundary so a refactor to `>` would fail.
		{
			name: "edge_idle_equals_threshold_sleeps",
			mutate: func(in *DecideInput) {
				in.LastNetworkActivity = now.Add(-15 * time.Minute) // == threshold
			},
			wantAction:  ActionSleep,
			wantReason:  "idle 15m >= threshold 15m",
			wantIdleGTE: 15,
		},
		// One minute below threshold must not sleep. Boundary check.
		{
			name: "edge_idle_one_below_threshold_protects",
			mutate: func(in *DecideInput) {
				in.LastNetworkActivity = now.Add(-14 * time.Minute) // 14m < 15m
			},
			wantAction: ActionNothing,
			wantReason: "below threshold",
		},
		// Idle one second over threshold: int(Minutes()) truncates so
		// 15m1s reports 15 → still >= threshold → sleeps. Codifies the
		// truncation, not rounding.
		{
			name: "edge_idle_one_second_over_threshold_still_sleeps",
			mutate: func(in *DecideInput) {
				in.LastNetworkActivity = now.Add(-(15*time.Minute + time.Second))
			},
			wantAction: ActionSleep,
			wantReason: "idle 15m >= threshold 15m",
		},
		// Anti-thrash boundary: sinceStart == 2*threshold exactly.
		// Impl uses `<` so equality is OUTSIDE the window → not
		// protected → falls through to the normal path.
		{
			name: "edge_anti_thrash_boundary_exact_2x_threshold",
			mutate: func(in *DecideInput) {
				in.LastStartedAt = now.Add(-30 * time.Minute) // == 2*15m
				in.LastNetworkActivity = now.Add(-30 * time.Minute)
			},
			wantAction:  ActionSleep,
			wantReason:  "idle 30m >= threshold 15m",
			wantIdleGTE: 30,
		},
		// Anti-thrash with LastStartedAt zero must fall through (the
		// `!in.LastStartedAt.IsZero()` guard). Zero time is "unknown",
		// not "just now" — sleep eligibility is decided by traffic.
		{
			name: "edge_anti_thrash_zero_last_started_falls_through",
			mutate: func(in *DecideInput) {
				in.LastStartedAt = time.Time{}
				in.LastNetworkActivity = now.Add(-90 * time.Minute) // idle 90m
			},
			wantAction:  ActionSleep,
			wantReason:  "idle 90m >= threshold 15m",
			wantIdleGTE: 90,
		},
		// State variants other than "Running" all short-circuit to
		// nothing. Spot-check a non-obvious one.
		{
			name:       "edge_frozen_state_short_circuits",
			mutate:     func(in *DecideInput) { in.State = "Frozen" },
			wantAction: ActionNothing,
			wantReason: "Frozen",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			in := mkInput()
			tc.mutate(&in)
			got := Decide(in)
			if got.Action != tc.wantAction {
				t.Fatalf("action = %q, want %q (reason=%q)", got.Action, tc.wantAction, got.Reason)
			}
			if tc.wantReason != "" && !strings.Contains(got.Reason, tc.wantReason) {
				t.Errorf("reason %q does not contain %q", got.Reason, tc.wantReason)
			}
			if tc.wantIdleGTE > 0 && got.IdleMinutes < tc.wantIdleGTE {
				t.Errorf("idle_minutes = %d, want >= %d", got.IdleMinutes, tc.wantIdleGTE)
			}
			if tc.wantAction == ActionNothing && got.IdleMinutes != 0 {
				t.Errorf("nothing-decision should have idle_minutes=0, got %d", got.IdleMinutes)
			}
		})
	}
}

// TestDecide_DeterministicForSameInput locks Decide's purity contract:
// repeated calls with the same input must return identical Decisions.
// A regression here is almost certainly a hidden global (time.Now,
// rand, package var) creeping into the function — exactly what the
// "no IO, clock from input only" rule guards against.
func TestDecide_DeterministicForSameInput(t *testing.T) {
	now := time.Date(2026, 5, 18, 12, 0, 0, 0, time.UTC)
	// Hand-picked deterministic permutations spanning the rules; we
	// avoid math/rand so failure reproduction needs no seed.
	inputs := []DecideInput{
		{State: "Running", AutoSleepEnabled: true, IdleThresholdMinutes: 15,
			LastNetworkActivity: now.Add(-90 * time.Minute), Now: now},
		{State: "Running", AutoSleepEnabled: true, IdleThresholdMinutes: 15,
			LastStartedAt: now.Add(-2 * time.Hour), Now: now},
		{State: "Running", AutoSleepEnabled: false, IdleThresholdMinutes: 15, Now: now},
		{State: "Stopped", AutoSleepEnabled: true, IdleThresholdMinutes: 15, Now: now},
		{State: "Running", AutoSleepEnabled: true, IsCoreRole: true,
			IdleThresholdMinutes: 15, Now: now},
		{State: "Running", AutoSleepEnabled: true, IdleThresholdMinutes: 15,
			LastStartedAt: now.Add(-5 * time.Minute), Now: now}, // anti-thrash
		{State: "Running", AutoSleepEnabled: true, IdleThresholdMinutes: 30,
			LastNetworkActivity: now.Add(-15 * time.Minute), Now: now}, // below
	}
	for i, in := range inputs {
		first := Decide(in)
		for run := 0; run < 100; run++ {
			got := Decide(in)
			if got != first {
				t.Fatalf("input[%d] non-deterministic on run %d: first=%+v got=%+v", i, run, first, got)
			}
		}
	}
}
