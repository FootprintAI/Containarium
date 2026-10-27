package audit

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/digitorus/timestamp"
)

// #2728: an RFC 3161 timestamp-authority anchor sink. Every test runs
// against fakeTSA, an in-process timestamp authority with its own CA; no
// real TSA is contacted.

// testTSA is a CA plus a TSA signing certificate issued by it.
type testTSA struct {
	ca      *x509.Certificate
	caKey   *ecdsa.PrivateKey
	leaf    *x509.Certificate
	leafKey *ecdsa.PrivateKey
}

func newTestTSA(t *testing.T, name string, eku []x509.ExtKeyUsage, notBefore, notAfter time.Time) *testTSA {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: name + " test root"},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(caDER)
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: name + " test TSA"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  eku,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(leafDER)
	return &testTSA{ca: ca, caKey: caKey, leaf: leaf, leafKey: leafKey}
}

func newValidTestTSA(t *testing.T, name string) *testTSA {
	return newTestTSA(t, name, []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
		time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
}

// pool is a trust bundle holding this TSA's root.
func (a *testTSA) pool() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(a.ca)
	return p
}

// writeBundle writes this TSA's root as a PEM trust bundle.
func (a *testTSA) writeBundle(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "tsa-bundle.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: a.ca.Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// response builds a granted TimeStampResp over digest.
func (a *testTSA) response(t *testing.T, digest []byte, nonce *big.Int, genTime time.Time, withCert bool) []byte {
	t.Helper()
	ts := timestamp.Timestamp{
		HashAlgorithm:     crypto.SHA256,
		HashedMessage:     digest,
		Time:              genTime,
		Nonce:             nonce,
		Policy:            []int{1, 2, 3, 4, 1},
		AddTSACertificate: withCert,
	}
	resp, err := ts.CreateResponseWithOpts(a.leaf, a.leafKey, crypto.SHA256)
	if err != nil {
		t.Fatalf("CreateResponse: %v", err)
	}
	return resp
}

// token is the TimeStampToken inside response(...).
func (a *testTSA) token(t *testing.T, digest []byte, genTime time.Time) []byte {
	t.Helper()
	ts, err := timestamp.ParseResponse(a.response(t, digest, big.NewInt(7), genTime, true))
	if err != nil {
		t.Fatalf("ParseResponse: %v", err)
	}
	return ts.RawToken
}

// fakeTSA answers RFC 3161 requests in-process. The knobs make it misbehave
// one way at a time.
type fakeTSA struct {
	t      *testing.T
	signer *testTSA

	mu          sync.Mutex
	calls       int
	down        bool
	errorStatus bool // answer with a "rejection" TimeStampResp
	wrongNonce  bool
	wrongDigest bool
	noCert      bool
	garbage     []byte // answer with these bytes instead
}

func (f *fakeTSA) post(_ context.Context, body []byte) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.down {
		return nil, errors.New("dial tcp: connection refused")
	}
	if f.garbage != nil {
		return f.garbage, nil
	}
	if f.errorStatus {
		r, err := timestamp.CreateErrorResponse(timestamp.Rejection, timestamp.SystemFailure)
		if err != nil {
			f.t.Fatal(err)
		}
		return r, nil
	}
	req, err := timestamp.ParseRequest(body)
	if err != nil {
		return nil, fmt.Errorf("fakeTSA: bad request: %w", err)
	}
	if req.HashAlgorithm != crypto.SHA256 || !req.Certificates || req.Nonce == nil {
		return nil, fmt.Errorf("fakeTSA: request must be SHA-256 with certReq and a nonce, got %+v", req)
	}
	digest := req.HashedMessage
	if f.wrongDigest {
		d := sha256.Sum256([]byte("something else"))
		digest = d[:]
	}
	nonce := req.Nonce
	if f.wrongNonce {
		nonce = new(big.Int).Add(nonce, big.NewInt(1))
	}
	return f.signer.response(f.t, digest, nonce, time.Now(), !f.noCert), nil
}

// newTSAFixture is a local file sink plus a TSA sink trusting `trusted`,
// stamped by a fake TSA signing with `signer`.
func newTSAFixture(t *testing.T, trusted, signer *testTSA) (*FileSink, *TSAAnchorSink, *fakeTSA) {
	t.Helper()
	file := tempSink(t)
	fake := &fakeTSA{t: t, signer: signer}
	sink, err := newTSAAnchorSink(file, "https://tsa.example.com/", trusted.pool(), fake.post)
	if err != nil {
		t.Fatalf("newTSAAnchorSink: %v", err)
	}
	return file, sink, fake
}

func TestCanonicalAnchorRecord_IsStable(t *testing.T) {
	got := string(CanonicalAnchorRecord(42, "abc"))
	if want := `{"checkpoint":42,"root":"abc"}`; got != want {
		t.Fatalf("CanonicalAnchorRecord = %s, want %s", got, want)
	}
}

func TestTSATokenDir(t *testing.T) {
	if got := TSATokenDir("/var/lib/x/anchors.jsonl"); got != "/var/lib/x/anchors.jsonl.tsa" {
		t.Fatalf("TSATokenDir = %q", got)
	}
}

func TestTSASink_PublishStoresAVerifiedToken(t *testing.T) {
	a := newValidTestTSA(t, "a")
	file, sink, fake := newTSAFixture(t, a, a)
	ctx := context.Background()
	if err := NewTeeSink(file, sink).PublishRoot(ctx, 10, "root-10"); err != nil {
		t.Fatalf("PublishRoot: %v", err)
	}
	tok, err := os.ReadFile(filepath.Join(TSATokenDir(file.path), "00000000000000000010.tsr"))
	if err != nil {
		t.Fatalf("token not stored: %v", err)
	}
	info, err := VerifyTSAToken(tok, a.pool(), AnchorRecordDigest(10, "root-10"))
	if err != nil {
		t.Fatalf("stored token does not verify: %v", err)
	}
	if info.GenTime.IsZero() {
		t.Fatal("GenTime not reported")
	}
	// Republishing the same record is a no-op: no second TSA request.
	if err := sink.PublishRoot(ctx, 10, "root-10"); err != nil {
		t.Fatalf("republish: %v", err)
	}
	if fake.calls != 1 {
		t.Fatalf("TSA calls = %d, want 1 (republish must not re-stamp)", fake.calls)
	}
	cp, root, ok, err := sink.LastPublished(ctx)
	if err != nil || !ok || cp != 10 || root != "root-10" {
		t.Fatalf("LastPublished = %d %q %v %v", cp, root, ok, err)
	}
}

func TestTSASink_ConflictingRootIsRejected(t *testing.T) {
	a := newValidTestTSA(t, "a")
	_, sink, _ := newTSAFixture(t, a, a)
	ctx := context.Background()
	if err := sink.PublishRoot(ctx, 10, "root-10"); err != nil {
		t.Fatal(err)
	}
	if err := sink.PublishRoot(ctx, 10, "other"); !errors.Is(err, ErrAnchorConflict) {
		t.Fatalf("err = %v, want ErrAnchorConflict", err)
	}
}

// Q4: whatever goes wrong at the TSA, the local file is written first and no
// token is stored; the manager retries on the next tick.
func TestTSASink_FailuresLeaveTheLocalFileAndStoreNoToken(t *testing.T) {
	a := newValidTestTSA(t, "a")
	other := newValidTestTSA(t, "other")
	tests := []struct {
		name    string
		signer  *testTSA
		set     func(*fakeTSA)
		wantErr error
		wantMsg string
	}{
		{name: "TSA down", signer: a, set: func(f *fakeTSA) { f.down = true }, wantMsg: "connection refused"},
		{name: "error status", signer: a, set: func(f *fakeTSA) { f.errorStatus = true }, wantMsg: "refused the request"},
		{name: "garbage reply", signer: a, set: func(f *fakeTSA) { f.garbage = []byte("not a token") }, wantErr: ErrTSATokenInvalid},
		{name: "nonce mismatch", signer: a, set: func(f *fakeTSA) { f.wrongNonce = true }, wantErr: ErrTSANonceMismatch},
		{name: "wrong hash", signer: a, set: func(f *fakeTSA) { f.wrongDigest = true }, wantErr: ErrTSAImprintMismatch},
		{name: "signer outside the trust bundle", signer: other, set: func(*fakeTSA) {}, wantErr: ErrTSAUntrustedSigner},
		{name: "no certificate in the token", signer: a, set: func(f *fakeTSA) { f.noCert = true }, wantErr: ErrTSATokenInvalid},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			file, sink, fake := newTSAFixture(t, a, tc.signer)
			tc.set(fake)
			err := NewTeeSink(file, sink).PublishRoot(context.Background(), 10, "root-10")
			if err == nil {
				t.Fatal("PublishRoot succeeded")
			}
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
			if tc.wantMsg != "" && !strings.Contains(strings.ToLower(err.Error()), tc.wantMsg) {
				t.Fatalf("err = %v, want it to mention %q", err, tc.wantMsg)
			}
			if cp, _, ok, _ := file.LastPublished(context.Background()); !ok || cp != 10 {
				t.Fatalf("local file = (%d, %v), want checkpoint 10 written first", cp, ok)
			}
			entries, _ := os.ReadDir(TSATokenDir(file.path))
			for _, e := range entries {
				t.Errorf("token directory holds %s after a failed stamp", e.Name())
			}
			// The next tick, with the TSA healthy, stores the token.
			if tc.signer == a {
				*fake = fakeTSA{t: t, signer: a}
				if err := NewTeeSink(file, sink).PublishRoot(context.Background(), 10, "root-10"); err != nil {
					t.Fatalf("retry: %v", err)
				}
			}
		})
	}
}

func TestVerifyTSAToken(t *testing.T) {
	a := newValidTestTSA(t, "a")
	other := newValidTestTSA(t, "other")
	noEKU := newTestTSA(t, "no-eku", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	digest := AnchorRecordDigest(10, "root-10")
	good := a.token(t, digest, time.Now())

	flipped := append([]byte(nil), good...)
	flipped[len(flipped)-5] ^= 0xff // inside the signature

	tests := []struct {
		name    string
		token   []byte
		trust   *x509.CertPool
		digest  []byte
		wantErr error
	}{
		{"valid", good, a.pool(), digest, nil},
		{"tampered local record (wrong hash)", good, a.pool(), AnchorRecordDigest(10, "rewritten"), ErrTSAImprintMismatch},
		{"signer outside the trust bundle", good, other.pool(), digest, ErrTSAUntrustedSigner},
		{"bad signature", flipped, a.pool(), digest, ErrTSATokenInvalid},
		{"truncated", good[:len(good)/2], a.pool(), digest, ErrTSATokenInvalid},
		{"empty", nil, a.pool(), digest, ErrTSATokenInvalid},
		// genTime before the TSA certificate's notBefore: the chain is
		// checked at genTime, not now, so this must fail.
		{"genTime outside the certificate validity", a.token(t, digest, time.Now().Add(-2*time.Hour)), a.pool(), digest, ErrTSAUntrustedSigner},
		{"TSA certificate without the timeStamping EKU", noEKU.token(t, digest, time.Now()), noEKU.pool(), digest, ErrTSAUntrustedSigner},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := VerifyTSAToken(tc.token, tc.trust, tc.digest)
			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("err = %v, want nil", err)
				}
				return
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

// pkcs7's BER transcoder at the pinned version predates the upstream fix for
// children that overrun their parent; the strict DER check rejects those
// inputs before pkcs7 sees them. Inputs from the upstream regression test.
// hostileDER are encodings the strict DER gate must refuse before pkcs7's
// BER transcoder sees them: the upstream regression inputs from
// digitorus/pkcs7#23 (ber_security_test.go and the malformed-BER no-panic
// test), plus DER-rule violations of our own.
func hostileDER() map[string][]byte {
	deepIndefinite := append([]byte{0x30, 0x02}, bytes.Repeat([]byte{0x30, 0x80}, 502)...)
	return map[string][]byte{
		// upstream TestBer2DerParentBoundaries
		"primitive content":      {0x30, 0x02, 0x04, 0x01, 0x41},
		"constructed content":    {0x30, 0x02, 0x30, 0x02, 0x05, 0x00},
		"overlapping siblings":   {0x30, 0x06, 0x30, 0x02, 0x30, 0x02, 0x05, 0x00},
		"child length byte":      {0x30, 0x01, 0x05, 0x00},
		"child high tag":         {0x30, 0x02, 0x1f, 0x81, 0x00, 0x00},
		"child long length":      {0x30, 0x02, 0x04, 0x81, 0x80},
		"EOC outside parent":     {0x30, 0x02, 0x30, 0x80, 0x00, 0x00},
		"EOC split at parent":    {0x30, 0x03, 0x30, 0x80, 0x00, 0x00},
		"indefinite ancestor":    {0x30, 0x80, 0x30, 0x02, 0x04, 0x01, 0x41, 0x00, 0x00},
		"32 bit length overflow": {0x30, 0x84, 0x7f, 0xff, 0xff, 0xff},
		// upstream TestBer2DerRejectsBeforeReadingOutsideParent
		"502-deep indefinite run": deepIndefinite,
		// DER rules
		"indefinite length":       {0x30, 0x80, 0x05, 0x00, 0x00, 0x00},
		"indefinite inside":       {0x30, 0x04, 0x30, 0x80, 0x00, 0x00},
		"trailing data":           {0x05, 0x00, 0x00},
		"non-minimal long length": {0x04, 0x81, 0x01, 0x41},
	}
}

// The gate must run in VerifyTSAToken before any parse: every hostile input
// fails with ErrTSANotStrictDER, which only the gate produces. (A pkcs7 parse
// error alone would carry ErrTSATokenInvalid but not this.)
func TestCheckStrictDER_RejectsMalformedEncodings(t *testing.T) {
	for name, in := range hostileDER() {
		if err := checkStrictDER(in); err == nil {
			t.Errorf("%s: accepted", name)
		}
		_, err := VerifyTSAToken(in, x509.NewCertPool(), make([]byte, 32))
		if !errors.Is(err, ErrTSANotStrictDER) || !errors.Is(err, ErrTSATokenInvalid) {
			t.Errorf("%s: VerifyTSAToken err = %v, want ErrTSANotStrictDER and ErrTSATokenInvalid", name, err)
		}
	}
	if err := checkStrictDER([]byte{0x30, 0x02, 0x05, 0x00}); err != nil {
		t.Fatalf("valid DER rejected: %v", err)
	}
}

// The gate must run in stamp before timestamp.ParseResponse: a hostile reply
// fails with ErrTSANotStrictDER and stores nothing.
func TestTSASink_HostileReplyIsRefusedByTheDERGate(t *testing.T) {
	a := newValidTestTSA(t, "a")
	for name, in := range hostileDER() {
		t.Run(name, func(t *testing.T) {
			file, sink, fake := newTSAFixture(t, a, a)
			fake.garbage = in
			err := NewTeeSink(file, sink).PublishRoot(context.Background(), 10, "root-10")
			if !errors.Is(err, ErrTSANotStrictDER) {
				t.Fatalf("err = %v, want ErrTSANotStrictDER", err)
			}
			if entries, _ := os.ReadDir(sink.TokenDir()); len(entries) != 0 {
				t.Fatalf("token directory holds %d entries after a hostile reply", len(entries))
			}
		})
	}
}

func TestCheckStrictDER_DepthLimit(t *testing.T) {
	// maxTSADERDepth+1 nested SEQUENCEs around a NULL.
	inner := []byte{0x05, 0x00}
	for i := 0; i <= maxTSADERDepth; i++ {
		inner = wrapSequence(inner)
	}
	if err := checkStrictDER(inner); err == nil {
		t.Fatal("nesting past the depth limit accepted")
	}
	ok := []byte{0x05, 0x00}
	for i := 0; i < maxTSADERDepth; i++ {
		ok = wrapSequence(ok)
	}
	if err := checkStrictDER(ok); err != nil {
		t.Fatalf("nesting at the depth limit rejected: %v", err)
	}
}

// wrapSequence wraps b in a short-form SEQUENCE; the depth tests stay well
// under 128 bytes.
func wrapSequence(b []byte) []byte {
	if len(b) >= 0x80 {
		panic("wrapSequence: content too long for a short-form length")
	}
	return append([]byte{0x30, byte(len(b))}, b...) // #nosec G115 -- len(b) < 0x80
}

func TestLoadTSATrustBundle(t *testing.T) {
	a := newValidTestTSA(t, "a")
	if _, err := LoadTSATrustBundle(a.writeBundle(t)); err != nil {
		t.Fatalf("valid bundle: %v", err)
	}
	empty := filepath.Join(t.TempDir(), "empty.pem")
	if err := os.WriteFile(empty, []byte("no certificates here\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadTSATrustBundle(empty); err == nil {
		t.Fatal("a bundle with no certificates was accepted")
	}
	if _, err := LoadTSATrustBundle(filepath.Join(t.TempDir(), "missing.pem")); err == nil {
		t.Fatal("a missing bundle was accepted")
	}
}

func TestTSAAnchorSinkFor(t *testing.T) {
	a := newValidTestTSA(t, "a")
	bundle := a.writeBundle(t)
	file := tempSink(t)
	tests := []struct {
		name, url, bundle string
		wantSink          bool
		wantErr           string
	}{
		{name: "neither set: no TSA sink"},
		{name: "both set", url: "https://tsa.example.com/", bundle: bundle, wantSink: true},
		{name: "plain http is allowed (the token is self-authenticating)", url: "http://tsa.example.com/", bundle: bundle, wantSink: true},
		{name: "URL without a bundle", url: "https://tsa.example.com/", wantErr: "trust bundle"},
		{name: "bundle without a URL", bundle: bundle, wantErr: "URL"},
		{name: "not http", url: "ftp://tsa.example.com/", bundle: bundle, wantErr: "http"},
		{name: "no host", url: "https:///path", bundle: bundle, wantErr: "host"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s, err := TSAAnchorSinkFor(file, tc.url, tc.bundle)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want it to mention %q", err, tc.wantErr)
				}
				if s != nil {
					t.Fatal("sink returned with an error")
				}
				return
			}
			if err != nil {
				t.Fatalf("err = %v", err)
			}
			if (s != nil) != tc.wantSink {
				t.Fatalf("sink = %v, want present=%v", s, tc.wantSink)
			}
		})
	}
}

// The real HTTP path: request shape, status handling and size limit, against
// an httptest server on loopback.
func TestHTTPTSAPost(t *testing.T) {
	a := newValidTestTSA(t, "a")
	var gotCT string
	var status = http.StatusOK
	var body []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotCT = r.Header.Get("Content-Type")
		if r.Method != http.MethodPost {
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return
		}
		w.WriteHeader(status)
		_, _ = w.Write(body)
	}))
	defer srv.Close()
	post := newHTTPTSAPost(srv.Client(), srv.URL)

	body = a.response(t, make([]byte, 32), big.NewInt(1), time.Now(), true)
	got, err := post(context.Background(), []byte{0x30, 0x00})
	if err != nil || len(got) != len(body) {
		t.Fatalf("post = %d bytes, %v", len(got), err)
	}
	if gotCT != "application/timestamp-query" {
		t.Fatalf("Content-Type = %q", gotCT)
	}

	status = http.StatusServiceUnavailable
	if _, err := post(context.Background(), nil); err == nil || !strings.Contains(err.Error(), "503") {
		t.Fatalf("err = %v, want HTTP 503", err)
	}

	status = http.StatusOK
	body = make([]byte, maxTSAResponseBytes+1)
	if _, err := post(context.Background(), nil); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Fatalf("err = %v, want a size error", err)
	}
}

func TestHTTPTSAPost_DoesNotFollowRedirects(t *testing.T) {
	hit := false
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hit = true }))
	defer target.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	if _, err := newHTTPTSAPost(nil, srv.URL)(context.Background(), nil); err == nil {
		t.Fatal("a redirect was followed or accepted")
	}
	if hit {
		t.Fatal("the redirect target was contacted")
	}
}

func TestComposeAnchorSink(t *testing.T) {
	a := newValidTestTSA(t, "a")
	file, tsa, _ := newTSAFixture(t, a, a)
	bucket := newTestGCSSink(t, newFakeGcloud())
	if got := ComposeAnchorSink(file, nil, nil); got != RootSink(file) {
		t.Fatalf("no externals: got %T, want the file sink itself", got)
	}
	for name, tc := range map[string]struct {
		bucket *GCSAnchorSink
		tsa    *TSAAnchorSink
		want   int
	}{
		"bucket only": {bucket, nil, 1},
		"TSA only":    {nil, tsa, 1},
		"both":        {bucket, tsa, 2},
	} {
		tee, ok := ComposeAnchorSink(file, tc.bucket, tc.tsa).(*TeeSink)
		if !ok || tee.file != RootSink(file) || len(tee.externals) != tc.want {
			t.Fatalf("%s: got %+v, want a tee over the file with %d external(s)", name, tee, tc.want)
		}
	}
}
