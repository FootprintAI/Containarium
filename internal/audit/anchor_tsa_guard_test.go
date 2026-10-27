package audit

import (
	"context"
	"crypto"
	"crypto/sha512"
	"encoding/asn1"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/digitorus/pkcs7"
	"github.com/digitorus/timestamp"
)

// #2728 review of #3150: guards on stored token files and on the token
// shape that other tests did not pin.

// The gate must run on the verify-anchor path too: a hostile .tsr on disk is
// a token-invalid finding carrying ErrTSANotStrictDER.
func TestVerifyAnchorsAgainstTSA_HostileTokenFileHitsTheDERGate(t *testing.T) {
	for name, in := range hostileDER() {
		t.Run(name, func(t *testing.T) {
			f := newTSAVerifyFixture(t, 30)
			f.anchor(10)
			if err := os.WriteFile(filepath.Join(f.sink.TokenDir(), tsaTokenName(10)), in, 0o600); err != nil {
				t.Fatal(err)
			}
			r := f.verify(f.chain)
			if len(r.Failures) == 0 || r.Failures[0].Kind != TSAFindingTokenInvalid || !errors.Is(r.Failures[0].Err, ErrTSANotStrictDER) {
				t.Fatalf("failures = %+v, want token-invalid with ErrTSANotStrictDER", r.Failures)
			}
		})
	}
}

// allocDuring reports the bytes allocated while f runs.
func allocDuring(f func()) uint64 {
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	f()
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}

// maxReadAlloc is far above one capped read and far below the 1 GiB files.
const maxReadAlloc = 64 << 20

// writeSparse makes a file of size bytes without writing them.
func writeSparse(t *testing.T, path string, size int64) {
	t.Helper()
	fh, err := os.Create(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	if err := fh.Truncate(size); err != nil {
		t.Fatal(err)
	}
	if err := fh.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestReadTokenFile_RefusesOversizedAndNonRegular(t *testing.T) {
	dir := t.TempDir()
	big := filepath.Join(dir, "big.tsr")
	writeSparse(t, big, 1<<30) // 1 GiB sparse: must not be read whole
	var err error
	if n := allocDuring(func() { _, err = readTokenFile(big) }); n > maxReadAlloc {
		t.Fatalf("reading an oversized token allocated %d bytes; the read must stop at the cap", n)
	}
	if !errors.Is(err, ErrTSATokenTooLarge) || !errors.Is(err, ErrTSATokenInvalid) {
		t.Fatalf("oversized: err = %v, want ErrTSATokenTooLarge", err)
	}
	exact := filepath.Join(dir, "exact.tsr")
	writeSparse(t, exact, maxTSAResponseBytes)
	if b, err := readTokenFile(exact); err != nil || len(b) != maxTSAResponseBytes {
		t.Fatalf("at the cap: %d bytes, %v", len(b), err)
	}
	sub := filepath.Join(dir, "dir.tsr")
	if err := os.Mkdir(sub, 0o750); err != nil {
		t.Fatal(err)
	}
	if _, err := readTokenFile(sub); !errors.Is(err, ErrTSATokenFileRefused) {
		t.Fatalf("directory: err = %v, want ErrTSATokenFileRefused", err)
	}
	// A symlink is refused even when it points at a regular file: the token
	// directory holds only files the daemon wrote.
	link := filepath.Join(dir, "link.tsr")
	if err := os.Symlink(exact, link); err != nil {
		t.Skipf("symlink: %v", err)
	}
	if _, err := readTokenFile(link); !errors.Is(err, ErrTSATokenFileRefused) {
		t.Fatalf("symlink: err = %v, want ErrTSATokenFileRefused", err)
	}
}

func TestVerifyAnchorsAgainstTSA_OversizedTokenFileIsAFinding(t *testing.T) {
	f := newTSAVerifyFixture(t, 30)
	f.anchor(10, 20)
	writeSparse(t, filepath.Join(f.sink.TokenDir(), tsaTokenName(10)), 1<<30)
	var r TSAAnchorReport
	if n := allocDuring(func() { r = f.verify(f.chain) }); n > maxReadAlloc {
		t.Fatalf("verify allocated %d bytes on an oversized token; the read must stop at the cap", n)
	}
	if !hasTSAFinding(r.Failures, TSAFindingTokenInvalid, 10) || !errors.Is(r.Failures[0].Err, ErrTSATokenTooLarge) {
		t.Fatalf("failures = %+v, want token-invalid with ErrTSATokenTooLarge at 10", r.Failures)
	}
	if r.StampedCheckpoints != 1 {
		t.Fatalf("stamped = %d, want checkpoint 20 still checked", r.StampedCheckpoints)
	}
}

func TestTSASink_OversizedExistingTokenIsRefusedNotOverwritten(t *testing.T) {
	a := newValidTestTSA(t, "a")
	file, sink, fake := newTSAFixture(t, a, a)
	if err := os.MkdirAll(sink.TokenDir(), 0o750); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(sink.TokenDir(), tsaTokenName(10))
	writeSparse(t, path, 1<<30)
	err := NewTeeSink(file, sink).PublishRoot(context.Background(), 10, "root-10")
	if !errors.Is(err, ErrTSATokenTooLarge) {
		t.Fatalf("err = %v, want ErrTSATokenTooLarge", err)
	}
	if fake.calls != 0 {
		t.Fatalf("TSA called %d times; an unreadable existing token must not be re-stamped", fake.calls)
	}
}

func TestRecoverParse_TurnsAPanicIntoAnError(t *testing.T) {
	_, err := recoverParse(func() (int, error) { panic("boom") })
	if err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("err = %v, want the panic as an error", err)
	}
}

func TestVerifyTSAToken_SizeCapRunsBeforeParsing(t *testing.T) {
	a := newValidTestTSA(t, "a")
	_, err := VerifyTSAToken(make([]byte, maxTSAResponseBytes+1), a.pool(), make([]byte, 32))
	if !errors.Is(err, ErrTSATokenTooLarge) {
		t.Fatalf("err = %v, want ErrTSATokenTooLarge", err)
	}
}

// A token over a SHA-512 imprint is refused as invalid, not compared.
func TestVerifyTSAToken_RequiresSHA256Imprint(t *testing.T) {
	a := newValidTestTSA(t, "a")
	d := sha512.Sum512(CanonicalAnchorRecord(10, "root-10"))
	ts := timestamp.Timestamp{HashAlgorithm: crypto.SHA512, HashedMessage: d[:], Time: time.Now(), Nonce: big.NewInt(1), Policy: []int{1, 2, 3}, AddTSACertificate: true}
	resp, err := ts.CreateResponseWithOpts(a.leaf, a.leafKey, crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := timestamp.ParseResponse(resp)
	if err != nil {
		t.Fatal(err)
	}
	_, err = VerifyTSAToken(parsed.RawToken, a.pool(), AnchorRecordDigest(10, "root-10"))
	if !errors.Is(err, ErrTSATokenInvalid) || errors.Is(err, ErrTSAImprintMismatch) || !strings.Contains(err.Error(), "SHA-256") {
		t.Fatalf("err = %v, want invalid (not SHA-256), not an imprint mismatch", err)
	}
}

// A token with two valid signers from the trusted TSA is refused.
func TestVerifyTSAToken_RequiresExactlyOneSigner(t *testing.T) {
	a := newValidTestTSA(t, "a")
	digest := AnchorRecordDigest(10, "root-10")
	p7, err := pkcs7.Parse(a.token(t, digest, time.Now()))
	if err != nil {
		t.Fatal(err)
	}
	sd, err := pkcs7.NewSignedData(p7.Content)
	if err != nil {
		t.Fatal(err)
	}
	sd.SetDigestAlgorithm(pkcs7.OIDDigestAlgorithmSHA256)
	sd.SetContentType(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4})
	for i := 0; i < 2; i++ {
		if err := sd.AddSigner(a.leaf, a.leafKey, pkcs7.SignerInfoConfig{}); err != nil {
			t.Fatal(err)
		}
	}
	two, err := sd.Finish()
	if err != nil {
		t.Fatal(err)
	}
	_, err = VerifyTSAToken(two, a.pool(), digest)
	if !errors.Is(err, ErrTSATokenInvalid) || !strings.Contains(err.Error(), "signers") {
		t.Fatalf("err = %v, want invalid for two signers", err)
	}
}

// writeTokenOnce never replaces an existing token.
func TestWriteTokenOnce_NeverOverwrites(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, tsaTokenName(10))
	if err := writeTokenOnce(dir, path, []byte("first")); err != nil {
		t.Fatal(err)
	}
	if err := writeTokenOnce(dir, path, []byte("second")); !errors.Is(err, os.ErrExist) {
		t.Fatalf("second write err = %v, want os.ErrExist", err)
	}
	if got := readFile(t, path); got != "first" {
		t.Fatalf("token = %q, want the first write kept", got)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("directory holds %d entries, want 1 (no stray temp files)", len(entries))
	}
}
