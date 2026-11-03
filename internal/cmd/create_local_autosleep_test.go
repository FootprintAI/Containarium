//go:build !containarium_client

package cmd

import (
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/footprintai/containarium/pkg/core/incus"
)

func TestStampLocalBirthAutoSleep(t *testing.T) {
	type call struct{ key, value string }
	for _, tc := range []struct {
		name         string
		minutes      int32
		failKey      string
		expectedKeys []string
	}{
		{
			name:         "successful birth policy",
			minutes:      60,
			expectedKeys: []string{incus.LastStartedAtKey, incus.IdleThresholdMinutesKey, incus.AutoSleepEnabledKey},
		},
		{
			name:    "default off",
			minutes: 0,
		},
		{
			name:         "clock failure never enables policy",
			minutes:      1,
			failKey:      incus.LastStartedAtKey,
			expectedKeys: []string{incus.LastStartedAtKey},
		},
		{
			name:         "threshold failure leaves policy disabled",
			minutes:      60,
			failKey:      incus.IdleThresholdMinutesKey,
			expectedKeys: []string{incus.LastStartedAtKey, incus.IdleThresholdMinutesKey},
		},
		{
			name:         "enable failure after threshold",
			minutes:      15,
			failKey:      incus.AutoSleepEnabledKey,
			expectedKeys: []string{incus.LastStartedAtKey, incus.IdleThresholdMinutesKey, incus.AutoSleepEnabledKey},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls []call
			before := time.Now().UTC()
			setConfig := func(containerName, key, value string) error {
				if containerName != "alice-container" {
					t.Fatalf("unexpected container %q", containerName)
				}
				calls = append(calls, call{key, value})
				if key == tc.failKey {
					return errors.New("simulated config failure")
				}
				return nil
			}
			stampLocalBirthAutoSleep(setConfig, "alice-container", tc.minutes)
			if len(calls) != len(tc.expectedKeys) {
				t.Fatalf("calls: %+v, want keys %v", calls, tc.expectedKeys)
			}
			for i, key := range tc.expectedKeys {
				if calls[i].key != key {
					t.Fatalf("call %d key = %q, want %q", i, calls[i].key, key)
				}
			}
			if tc.minutes > 0 {
				stamped, err := time.Parse(time.RFC3339, calls[0].value)
				if err != nil || stamped.Before(before.Add(-time.Second)) || stamped.After(time.Now().Add(time.Second)) {
					t.Fatalf("UTC birth clock %q invalid or out of bounds: %v", calls[0].value, err)
				}
			}
			if len(calls) >= 2 && calls[1].value != strconv.Itoa(int(tc.minutes)) {
				t.Fatalf("threshold = %q, want %d", calls[1].value, tc.minutes)
			}
			if len(calls) == 3 && calls[2].value != "true" {
				t.Fatalf("unexpected auto-sleep enable value: %+v", calls)
			}
		})
	}
}
