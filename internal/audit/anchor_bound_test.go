package audit

import (
	"context"
	"errors"
	"testing"
)

// stubSink is a RootSink with a fixed latest record.
type stubSink struct {
	cp   int64
	root string
	ok   bool
	err  error
}

func (stubSink) PublishRoot(context.Context, int64, string) error { return errors.New("read-only") }
func (s stubSink) LastPublished(context.Context) (int64, string, bool, error) {
	return s.cp, s.root, s.ok, s.err
}

func TestSafeAnchor(t *testing.T) {
	tests := []struct {
		name     string
		file     stubSink
		external RootSink
		want     PurgeAnchor
		wantOK   bool
		wantErr  bool
	}{
		{"nothing anchored", stubSink{}, nil, PurgeAnchor{}, false, false},
		{"file only", stubSink{cp: 40, root: "f40", ok: true}, nil, PurgeAnchor{40, "f40"}, true, false},
		{"bucket behind the file bounds the purge", stubSink{cp: 40, root: "f40", ok: true}, stubSink{cp: 30, root: "b30", ok: true}, PurgeAnchor{30, "b30"}, true, false},
		{"a planted object above the tip cannot raise the bound", stubSink{cp: 40, root: "f40", ok: true}, stubSink{cp: 9223372036854775807, root: "planted", ok: true}, PurgeAnchor{40, "f40"}, true, false},
		{"same checkpoint, same root", stubSink{cp: 40, root: "r", ok: true}, stubSink{cp: 40, root: "r", ok: true}, PurgeAnchor{40, "r"}, true, false},
		{"same checkpoint, different roots", stubSink{cp: 40, root: "a", ok: true}, stubSink{cp: 40, root: "b", ok: true}, PurgeAnchor{}, false, true},
		{"an empty bucket means nothing is safe yet", stubSink{cp: 40, root: "f40", ok: true}, stubSink{}, PurgeAnchor{}, false, false},
		{"a bucket failure is an error, never no anchor", stubSink{cp: 40, root: "f40", ok: true}, stubSink{err: errors.New("403")}, PurgeAnchor{}, false, true},
		{"a file failure is an error", stubSink{err: errors.New("io")}, nil, PurgeAnchor{}, false, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok, err := SafeAnchor(context.Background(), tc.file, tc.external)
			if (err != nil) != tc.wantErr || ok != tc.wantOK || got != tc.want {
				t.Fatalf("SafeAnchor = %+v ok=%v err=%v, want %+v ok=%v err=%v", got, ok, err, tc.want, tc.wantOK, tc.wantErr)
			}
		})
	}
}
