package guardrail

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"unicode/utf8"

	pb "github.com/footprintai/containarium/pkg/pb/containarium/v1"
)

// LoadUnits turns a directory into text units, one per regular file, keyed
// by slash-separated relative path. A file that is not valid UTF-8 is not
// repaired and not silently skipped: it becomes a gap, which fails the gate,
// because a lenient decode would hand the engine quietly corrupted text.
func LoadUnits(dir string) ([]*pb.GuardrailTextUnit, []*pb.GuardrailScanGap, error) {
	var units []*pb.GuardrailTextUnit
	var gaps []*pb.GuardrailScanGap
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		info, err := os.Stat(p)
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return err
		}
		id := filepath.ToSlash(rel)
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		if !utf8.Valid(b) {
			gaps = append(gaps, &pb.GuardrailScanGap{UnitId: id, Detail: "not valid UTF-8; not scanned"})
			return nil
		}
		units = append(units, &pb.GuardrailTextUnit{UnitId: id, Text: string(b)})
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	sort.Slice(units, func(i, j int) bool { return units[i].UnitId < units[j].UnitId })
	return units, gaps, nil
}

// WriteUnits writes wiped text under out, mirroring the unit ids as
// relative paths. Files are 0600 in 0700 directories: the output is the
// data minus what the engine found, which is still the data.
func WriteUnits(out string, wiped map[string]string) error {
	for id, text := range wiped {
		p := filepath.Join(out, filepath.FromSlash(id))
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			return err
		}
		if err := os.WriteFile(p, []byte(text), 0o600); err != nil {
			return fmt.Errorf("guardrail: write %s: %w", p, err)
		}
	}
	return nil
}
