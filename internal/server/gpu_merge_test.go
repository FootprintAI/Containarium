package server

import (
	"reflect"
	"testing"
)

func TestMergeGPURequests(t *testing.T) {
	cases := []struct {
		name string
		gpus []string
		gpu  string
		want []string
	}{
		{"neither set", nil, "", nil},
		{"singular promoted to list", nil, "0", []string{"0"}},
		{"repeated wins", []string{"0", "1"}, "", []string{"0", "1"}},
		{"repeated supersedes singular", []string{"0", "1"}, "2", []string{"0", "1"}},
		{"empty singular ignored", nil, "", nil},
		{"single-element repeated", []string{"0000:01:00.0"}, "", []string{"0000:01:00.0"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := mergeGPURequests(c.gpus, c.gpu)
			if !reflect.DeepEqual(got, c.want) {
				t.Errorf("mergeGPURequests(%v, %q) = %v, want %v", c.gpus, c.gpu, got, c.want)
			}
		})
	}
}
