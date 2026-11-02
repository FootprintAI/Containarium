package backup

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"runtime"
	"testing"
	"time"
)

// manyExcludedArchive streams a box with n small files under /var/cache and
// n/10 kept files. Nothing is buffered here, so the filter's own cost is
// what the benchmark sees.
func manyExcludedArchive(n int) io.Reader {
	pr, pw := io.Pipe()
	go func() {
		gz, _ := gzip.NewWriterLevel(pw, gzip.BestSpeed)
		tw := tar.NewWriter(gz)
		body := make([]byte, 2048)
		write := func(name string) bool {
			if err := tw.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(body))}); err != nil {
				pw.CloseWithError(err)
				return false
			}
			if _, err := tw.Write(body); err != nil {
				pw.CloseWithError(err)
				return false
			}
			return true
		}
		for i := 0; i < n; i++ {
			if !write(fmt.Sprintf("backup/container/rootfs/var/cache/apt/d%d/f%d", i%1000, i)) {
				return
			}
			if i%10 == 0 && !write(fmt.Sprintf("backup/container/rootfs/srv/d%d/f%d", i%1000, i)) {
				return
			}
		}
		_ = tw.Close()
		pw.CloseWithError(gz.Close())
	}()
	return pr
}

// BenchmarkFilterBoxArchive_ManyExcludedFiles measures the cost of the
// spill (one age.Encrypt per excluded file, one map entry per file) on a box
// with many small files under /var/cache (#3126). Run:
//
//	go test ./pkg/core/backup -run '^$' -bench ManyExcluded -benchtime 1x
func BenchmarkFilterBoxArchive_ManyExcludedFiles(b *testing.B) {
	for _, n := range []int{10_000, 100_000} {
		b.Run(fmt.Sprintf("%d_excluded_files", n), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				runtime.GC()
				var before runtime.MemStats
				runtime.ReadMemStats(&before)
				start := time.Now()
				err := filterBoxArchive(manyExcludedArchive(n), io.Discard, "bench", time.Now(), 1<<40, b.TempDir())
				if err != nil {
					b.Fatal(err)
				}
				var after runtime.MemStats
				runtime.ReadMemStats(&after)
				b.ReportMetric(float64(time.Since(start).Microseconds())/float64(n), "us/excluded-file")
				b.ReportMetric(float64(after.TotalAlloc-before.TotalAlloc)/float64(n), "alloc-B/excluded-file")
			}
		})
	}
}
