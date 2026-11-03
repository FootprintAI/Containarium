package audit

import (
	"context"
	"testing"
	"time"
)

// Syslog stamps ("Dec 31 23:50:00") carry no year, and auth.log read in early
// January still holds December's lines. Those lines must be dated last year:
// dated this year they sit eleven months in the future, and the collector's
// high-water mark then hides every real login until that December.

func TestParseSyslogStamp_ResolvesTheYear(t *testing.T) {
	newYear := time.Date(2027, time.January, 1, 0, 5, 0, 0, time.UTC)
	cases := []struct {
		name  string
		stamp string
		now   time.Time
		want  time.Time
	}{
		{
			name:  "a line from earlier this year",
			stamp: "Mar 12 14:30:01",
			now:   time.Date(2026, time.August, 9, 12, 0, 0, 0, time.UTC),
			want:  time.Date(2026, time.March, 12, 14, 30, 1, 0, time.UTC),
		},
		{
			name:  "December's line read on New Year's Day",
			stamp: "Dec 31 23:50:00",
			now:   newYear,
			want:  time.Date(2026, time.December, 31, 23, 50, 0, 0, time.UTC),
		},
		{
			name:  "a line written just now in the new year",
			stamp: "Jan  1 00:04:00",
			now:   newYear,
			want:  time.Date(2027, time.January, 1, 0, 4, 0, 0, time.UTC),
		},
		{
			name:  "a log in a zone ahead of the reader stays in the current year",
			stamp: "Jan  1 10:00:00",
			now:   newYear,
			want:  time.Date(2027, time.January, 1, 10, 0, 0, 0, time.UTC),
		},
		{
			name:  "New Year's line from a box ahead of a reader still in the old year",
			stamp: "Jan  1 05:00:00",
			now:   time.Date(2026, time.December, 31, 23, 0, 0, 0, time.UTC),
			want:  time.Date(2027, time.January, 1, 5, 0, 0, 0, time.UTC),
		},
		{
			name:  "a reader in a zone behind UTC on New Year's Eve",
			stamp: "Jan  1 05:00:00",
			now:   time.Date(2026, time.December, 31, 20, 0, 0, 0, time.FixedZone("UTC-10", -10*3600)),
			want:  time.Date(2027, time.January, 1, 5, 0, 0, 0, time.UTC),
		},
		{
			name:  "unpadded single-digit day",
			stamp: "Mar 2 14:30:01",
			now:   time.Date(2026, time.August, 9, 12, 0, 0, 0, time.UTC),
			want:  time.Date(2026, time.March, 2, 14, 30, 1, 0, time.UTC),
		},
		{
			name:  "leap day read in the following, non-leap year",
			stamp: "Feb 29 08:00:00",
			now:   time.Date(2029, time.January, 3, 0, 0, 0, 0, time.UTC),
			want:  time.Date(2028, time.February, 29, 8, 0, 0, 0, time.UTC),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := parseSyslogStamp(tc.stamp, tc.now)
			if !ok {
				t.Fatalf("parseSyslogStamp(%q) did not parse", tc.stamp)
			}
			if !got.Equal(tc.want) {
				t.Errorf("parseSyslogStamp(%q, %v) = %v, want %v", tc.stamp, tc.now, got, tc.want)
			}
		})
	}
}

func TestParseSyslogStamp_RejectsGarbage(t *testing.T) {
	now := time.Date(2026, time.August, 9, 12, 0, 0, 0, time.UTC)
	for _, stamp := range []string{"", "Foo 12 14:30:01", "Feb 30 08:00:00", "Mar 12 25:00:00"} {
		if ts, ok := parseSyslogStamp(stamp, now); ok {
			t.Errorf("parseSyslogStamp(%q) = %v, want no parse", stamp, ts)
		}
	}
}

// Both year-less parsers go through the same resolution.
func TestParsers_DateDecemberLinesReadInJanuaryToLastYear(t *testing.T) {
	now := time.Date(2027, time.January, 1, 0, 5, 0, 0, time.UTC)
	want := time.Date(2026, time.December, 31, 23, 50, 0, 0, time.UTC)

	ts, _, _, _, ok := parseAuthLogLine(
		`Dec 31 23:50:00 host sshd[123]: Accepted publickey for alice from 10.0.0.7 port 54321 ssh2`, now)
	if !ok || !ts.Equal(want) {
		t.Errorf("sshd line: ts = %v, ok = %v; want %v", ts, ok, want)
	}

	ts, _, _, _, ok = parseDropbearLine(
		`Dec 31 23:50:00 Pubkey auth succeeded for 'alice' with ssh-ed25519 key SHA256:abc from 10.0.0.7:54321`,
		now, now)
	if !ok || !ts.Equal(want) {
		t.Errorf("dropbear line: ts = %v, ok = %v; want %v", ts, ok, want)
	}
}

// The failure the year resolution exists to prevent, end to end: a collector
// polling across New Year must keep recording the new year's logins.
func TestCollector_KeepsRecordingLoginsAcrossNewYear(t *testing.T) {
	store := newAuditStore(t)
	src := &fakeSource{
		boxes: []SessionBox{{Name: "alice-container", Username: "alice"}},
		logs: map[string]string{
			"alice-container": `Dec 31 23:50:00 host sshd[123]: Accepted publickey for alice from 10.0.0.7 port 54321 ssh2`,
		},
		parse: func(line string, now, _ time.Time) (time.Time, string, string, string, bool) {
			return parseAuthLogLine(line, now)
		},
	}
	sc := NewSSHCollectorWithSource(src, store)

	sc.now = func() time.Time { return time.Date(2026, time.December, 31, 23, 55, 0, 0, time.UTC) }
	sc.collectAll(context.Background())

	// The first poll after midnight still reads December's line from auth.log.
	src.logs["alice-container"] += "\n" +
		`Jan  1 00:10:00 host sshd[124]: Accepted publickey for alice from 10.0.0.8 port 54322 ssh2`
	sc.now = func() time.Time { return time.Date(2027, time.January, 1, 0, 12, 0, 0, time.UTC) }
	sc.collectAll(context.Background())

	if len(store.entries) != 2 {
		t.Fatalf("recorded %d entries across New Year, want 2 — December's login re-dated into "+
			"the new year would be recorded twice and hide later logins", len(store.entries))
	}
	got := store.entries[1]
	if got.SourceIP != "10.0.0.8" {
		t.Errorf("second entry is from %q, want the new year's login from 10.0.0.8", got.SourceIP)
	}
	if want := time.Date(2027, time.January, 1, 0, 10, 0, 0, time.UTC); !got.Timestamp.Equal(want) {
		t.Errorf("second entry dated %v, want %v", got.Timestamp, want)
	}
}
