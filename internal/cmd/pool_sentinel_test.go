//go:build !windows

package cmd

import (
	"errors"
	"testing"
	"time"
)

func TestParseSentinelCandidates(t *testing.T) {
	cands, err := parseSentinelCandidates([]string{"us=us.example.com:443", "plain.example.com:443", " eu = eu.example.com:443 "})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(cands) != 3 {
		t.Fatalf("want 3 candidates, got %d", len(cands))
	}
	if cands[0].Region != "us" || cands[0].Addr != "us.example.com:443" {
		t.Errorf("labeled parse wrong: %+v", cands[0])
	}
	if cands[1].Region != "" || cands[1].Addr != "plain.example.com:443" {
		t.Errorf("bare parse wrong: %+v", cands[1])
	}
	if cands[2].Region != "eu" || cands[2].Addr != "eu.example.com:443" {
		t.Errorf("whitespace-trim parse wrong: %+v", cands[2])
	}
}

func TestParseSentinelCandidates_Errors(t *testing.T) {
	for _, in := range [][]string{
		{},            // none
		{"=host:443"}, // empty region
		{"us="},       // empty addr
		{"   "},       // blank → none
	} {
		if _, err := parseSentinelCandidates(in); err == nil {
			t.Errorf("parseSentinelCandidates(%v) expected error", in)
		}
	}
}

func TestPickLowestRTT(t *testing.T) {
	rows := []rttRow{
		{Cand: sentinelCandidate{Region: "us", Addr: "a"}, RTT: 30 * time.Millisecond},
		{Cand: sentinelCandidate{Region: "eu", Addr: "b"}, RTT: 10 * time.Millisecond},
		{Cand: sentinelCandidate{Region: "ap", Addr: "c"}, Err: errors.New("timeout")},
	}
	got, err := pickLowestRTT(rows)
	if err != nil {
		t.Fatalf("pick: %v", err)
	}
	if got.Region != "eu" {
		t.Errorf("want eu (lowest RTT), got %+v", got)
	}
}

func TestPickLowestRTT_AllFailed(t *testing.T) {
	rows := []rttRow{
		{Cand: sentinelCandidate{Addr: "a"}, Err: errors.New("x")},
		{Cand: sentinelCandidate{Addr: "b"}, Err: errors.New("y")},
	}
	if _, err := pickLowestRTT(rows); err == nil {
		t.Error("all-failed must error, not silently pick none")
	}
}

func TestResolveSentinel_SingleSkipsProbe(t *testing.T) {
	probed := false
	probe := func([]sentinelCandidate) []rttRow { probed = true; return nil }
	c := []sentinelCandidate{{Region: "us", Addr: "only:443"}}
	got, rows, err := resolveSentinel(c, "auto", probe)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if probed {
		t.Error("single candidate must skip probing")
	}
	if got.Addr != "only:443" || rows != nil {
		t.Errorf("unexpected result: %+v rows=%v", got, rows)
	}
}

func TestResolveSentinel_AutoPicksLowest(t *testing.T) {
	c := []sentinelCandidate{{Region: "us", Addr: "u"}, {Region: "eu", Addr: "e"}}
	probe := func(cs []sentinelCandidate) []rttRow {
		return []rttRow{
			{Cand: cs[0], RTT: 50 * time.Millisecond},
			{Cand: cs[1], RTT: 5 * time.Millisecond},
		}
	}
	got, rows, err := resolveSentinel(c, "auto", probe)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got.Region != "eu" {
		t.Errorf("auto should pick lowest RTT (eu), got %+v", got)
	}
	if len(rows) != 2 {
		t.Errorf("expected probe table of 2 rows, got %d", len(rows))
	}
}

func TestResolveSentinel_NamedRegion(t *testing.T) {
	c := []sentinelCandidate{{Region: "us", Addr: "u"}, {Region: "eu", Addr: "e"}}
	got, _, err := resolveSentinel(c, "eu", nil)
	if err != nil || got.Addr != "e" {
		t.Fatalf("named region: got %+v err=%v", got, err)
	}
	if _, _, err := resolveSentinel(c, "nope", nil); err == nil {
		t.Error("unknown region must error")
	}
}

func TestResolveSentinel_MultipleNoRegionIsAmbiguous(t *testing.T) {
	c := []sentinelCandidate{{Addr: "a"}, {Addr: "b"}}
	if _, _, err := resolveSentinel(c, "", nil); err == nil {
		t.Error("multiple candidates with no --region must error (ambiguous), not pick arbitrarily")
	}
}
