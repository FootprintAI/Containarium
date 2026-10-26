package audit

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/digitorus/pkcs7"
	"github.com/digitorus/timestamp"
)

// #2728: an RFC 3161 timestamp-authority (TSA) anchor sink.
//
// The GCS sink (#2880) needs an object store with a retention lock. Where
// there is none, a TSA gives each anchor an external, signed proof of time:
// the TSA signs "this SHA-256 existed at genTime", and anyone holding the
// TSA's root certificate can check that signature later without trusting
// this host. The token does not hold the anchor itself, only its hash, so it
// is stored next to the local anchor file, one DER file per checkpoint:
//
//	<anchor-path>.tsa/<checkpoint, zero-padded to 20 digits>.tsr
//
// What the token proves, and what it does not, is in the operator runbook
// ("Anchoring to a timestamp authority"). In short: a host-root attacker who
// edits a stamped line in the local file is caught (the hash no longer
// matches), but one who deletes the token files, or the whole directory, is
// not caught by the tokens alone: the check can only warn that a checkpoint
// has no token.
//
// Decisions Q3-Q7 on #2728: the operator configures the TSA URL and trust
// bundle (no built-in TSA); requests go over net/http with a 60 s timeout;
// a failed stamp leaves the local record, stores nothing, and is retried on
// the next tick; every token is verified against the trust bundle before it
// is stored; a random 64-bit nonce is sent and checked; certReq is set so the
// token carries the TSA certificate; the chain is checked at genTime; no
// CRL/OCSP revocation check.

// tsaCallTimeout bounds one TSA request, like gcloudCallTimeout.
const tsaCallTimeout = 60 * time.Second

// maxTSAResponseBytes bounds a TSA reply. A token with its certificate chain
// is a few kilobytes.
const maxTSAResponseBytes = 256 << 10

// maxTSADERDepth bounds ASN.1 nesting in a token. A CMS SignedData with a
// certificate chain nests well under 20 deep.
const maxTSADERDepth = 32

var (
	// ErrTSATokenInvalid: the token or reply is malformed, its signature does
	// not verify, or it carries no TSA certificate.
	ErrTSATokenInvalid = errors.New("audit: timestamp token is invalid")
	// ErrTSAUntrustedSigner: the token's signing certificate does not chain to
	// the trust bundle at the token's genTime, or is not a timestamping
	// certificate.
	ErrTSAUntrustedSigner = errors.New("audit: timestamp token is not signed by a TSA in the trust bundle")
	// ErrTSAImprintMismatch: the token is valid but covers a different hash
	// than the anchor record it is checked against.
	ErrTSAImprintMismatch = errors.New("audit: timestamp token covers a different anchor record")
	// ErrTSANonceMismatch: the reply's nonce is not the one sent.
	ErrTSANonceMismatch = errors.New("audit: timestamp reply nonce does not match the request")
)

// canonicalAnchor is the exact record a TSA token covers. Field order is
// fixed by the struct, so the bytes are stable.
type canonicalAnchor struct {
	Checkpoint int64  `json:"checkpoint"`
	Root       string `json:"root"`
}

// CanonicalAnchorRecord is the byte string a TSA token's message imprint is
// the SHA-256 of: {"checkpoint":<id>,"root":"<root>"}, no whitespace.
func CanonicalAnchorRecord(checkpoint int64, root string) []byte {
	b, err := json.Marshal(canonicalAnchor{Checkpoint: checkpoint, Root: root})
	if err != nil {
		// Marshalling an int64 and a string cannot fail.
		panic(err)
	}
	return b
}

// AnchorRecordDigest is SHA-256(CanonicalAnchorRecord(checkpoint, root)).
func AnchorRecordDigest(checkpoint int64, root string) []byte {
	d := sha256.Sum256(CanonicalAnchorRecord(checkpoint, root))
	return d[:]
}

// TSATokenDir is where the tokens for the anchor file at anchorPath live.
func TSATokenDir(anchorPath string) string { return anchorPath + ".tsa" }

func tsaTokenName(checkpoint int64) string { return fmt.Sprintf("%020d.tsr", checkpoint) }

// TSATokenInfo is what a verified token says.
type TSATokenInfo struct {
	GenTime time.Time
	Imprint []byte
	Nonce   *big.Int
	Signer  string
}

// LoadTSATrustBundle reads a PEM file of the TSA root (and any intermediate)
// certificates tokens must chain to. A file with no certificate is an error.
func LoadTSATrustBundle(path string) (*x509.CertPool, error) {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("audit: read TSA trust bundle: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(data) {
		return nil, fmt.Errorf("audit: TSA trust bundle %s holds no PEM certificate", path)
	}
	return pool, nil
}

// VerifyTSAToken checks a TimeStampToken: well-formed DER, a valid signature
// by the certificate it carries, that certificate chaining to trust at the
// token's genTime with the timeStamping extended key usage, and a SHA-256
// message imprint equal to digest.
func VerifyTSAToken(token []byte, trust *x509.CertPool, digest []byte) (TSATokenInfo, error) {
	info, err := verifyTSATokenSignature(token, trust)
	if err != nil {
		return info, err
	}
	if !bytes.Equal(info.Imprint, digest) {
		return info, ErrTSAImprintMismatch
	}
	return info, nil
}

// verifyTSATokenSignature is VerifyTSAToken without the imprint comparison.
func verifyTSATokenSignature(token []byte, trust *x509.CertPool) (TSATokenInfo, error) {
	if trust == nil {
		return TSATokenInfo{}, fmt.Errorf("%w: no trust bundle", ErrTSAUntrustedSigner)
	}
	if len(token) == 0 || len(token) > maxTSAResponseBytes {
		return TSATokenInfo{}, fmt.Errorf("%w: token is empty or too large", ErrTSATokenInvalid)
	}
	// The pinned pkcs7 transcodes BER before parsing, and that transcoder
	// predates upstream's fix for children that overrun their parent. Only
	// strict DER reaches it.
	if err := checkStrictDER(token); err != nil {
		return TSATokenInfo{}, fmt.Errorf("%w: %v", ErrTSATokenInvalid, err)
	}
	// timestamp.Parse verifies the signature with the embedded certificate.
	ts, err := recoverParse(func() (*timestamp.Timestamp, error) { return timestamp.Parse(token) })
	if err != nil {
		return TSATokenInfo{}, fmt.Errorf("%w: %v", ErrTSATokenInvalid, err)
	}
	if !ts.AddTSACertificate || len(ts.Certificates) == 0 {
		return TSATokenInfo{}, fmt.Errorf("%w: the token carries no TSA certificate", ErrTSATokenInvalid)
	}
	if ts.HashAlgorithm != crypto.SHA256 {
		return TSATokenInfo{}, fmt.Errorf("%w: message imprint uses %v, not SHA-256", ErrTSATokenInvalid, ts.HashAlgorithm)
	}
	p7, err := recoverParse(func() (*pkcs7.PKCS7, error) { return pkcs7.Parse(token) })
	if err != nil {
		return TSATokenInfo{}, fmt.Errorf("%w: %v", ErrTSATokenInvalid, err)
	}
	if len(p7.Signers) != 1 {
		return TSATokenInfo{}, fmt.Errorf("%w: %d signers, want 1", ErrTSATokenInvalid, len(p7.Signers))
	}
	intermediates := x509.NewCertPool()
	for _, c := range p7.Certificates {
		intermediates.AddCert(c)
	}
	// Chain checked at genTime (Q6), so a token stays verifiable after the
	// TSA certificate expires.
	err = p7.VerifyWithOpts(x509.VerifyOptions{
		Roots:         trust,
		Intermediates: intermediates,
		CurrentTime:   ts.Time,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
	})
	if err != nil {
		return TSATokenInfo{}, fmt.Errorf("%w: %v", ErrTSAUntrustedSigner, err)
	}
	signer := ""
	if c := p7.GetOnlySigner(); c != nil {
		signer = c.Subject.String()
	}
	return TSATokenInfo{GenTime: ts.Time, Imprint: ts.HashedMessage, Nonce: ts.Nonce, Signer: signer}, nil
}

// recoverParse turns a parser panic on hostile input into an error.
func recoverParse[T any](f func() (T, error)) (v T, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("parser panic: %v", r)
		}
	}()
	return f()
}

// checkStrictDER accepts exactly one DER element: definite, minimal lengths
// only, every child inside its parent, nesting at most maxTSADERDepth.
func checkStrictDER(b []byte) error {
	rest, err := walkDER(b, 0)
	if err != nil {
		return err
	}
	if len(rest) > 0 {
		return errors.New("trailing data after the DER element")
	}
	return nil
}

func walkDER(b []byte, depth int) ([]byte, error) {
	if depth > maxTSADERDepth {
		return nil, errors.New("DER nesting too deep")
	}
	var v asn1.RawValue
	// encoding/asn1 rejects indefinite and non-minimal lengths and lengths
	// past the end of b.
	rest, err := asn1.Unmarshal(b, &v)
	if err != nil {
		return nil, err
	}
	if v.IsCompound {
		inner := v.Bytes
		for len(inner) > 0 {
			if inner, err = walkDER(inner, depth+1); err != nil {
				return nil, err
			}
		}
	}
	return rest, nil
}

// tsaPostFunc sends one DER TimeStampReq and returns the raw reply. A field
// on the sink so tests substitute a fake TSA.
type tsaPostFunc func(ctx context.Context, req []byte) ([]byte, error)

// newHTTPTSAPost posts to tsaURL over HTTP(S) with a 60 s timeout. Redirects
// are refused: the operator configured this URL.
func newHTTPTSAPost(base *http.Client, tsaURL string) tsaPostFunc {
	c := http.Client{}
	if base != nil {
		c = *base
	}
	c.Timeout = tsaCallTimeout
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	shown := redactURL(tsaURL)
	return func(ctx context.Context, body []byte) ([]byte, error) {
		ctx, cancel := context.WithTimeout(ctx, tsaCallTimeout)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, tsaURL, bytes.NewReader(body))
		if err != nil {
			return nil, fmt.Errorf("audit: build TSA request: %w", err)
		}
		req.Header.Set("Content-Type", "application/timestamp-query")
		req.Header.Set("Accept", "application/timestamp-reply")
		resp, err := c.Do(req)
		if err != nil {
			return nil, fmt.Errorf("audit: TSA %s: %w", shown, err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("audit: TSA %s returned HTTP %d", shown, resp.StatusCode)
		}
		data, err := io.ReadAll(io.LimitReader(resp.Body, maxTSAResponseBytes+1))
		if err != nil {
			return nil, fmt.Errorf("audit: read TSA %s reply: %w", shown, err)
		}
		if len(data) > maxTSAResponseBytes {
			return nil, fmt.Errorf("audit: TSA %s reply is larger than %d bytes", shown, maxTSAResponseBytes)
		}
		return data, nil
	}
}

func redactURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "<invalid URL>"
	}
	return u.Redacted()
}

// TSAAnchorSink is a RootSink that stamps each anchor record at an RFC 3161
// TSA and stores the verified token next to the local anchor file. It is
// always used behind a TeeSink after the FileSink it reads roots from.
type TSAAnchorSink struct {
	url   string // redacted, for logs
	trust *x509.CertPool
	local *FileSink
	dir   string
	post  tsaPostFunc
}

// TSAAnchorSinkFor builds the TSA sink from the daemon's configuration. Both
// empty means no TSA sink (nil, nil). One without the other is an error: a
// URL without a trust bundle would store tokens nobody checked.
func TSAAnchorSinkFor(local *FileSink, tsaURL, trustBundlePath string) (*TSAAnchorSink, error) {
	tsaURL, trustBundlePath = strings.TrimSpace(tsaURL), strings.TrimSpace(trustBundlePath)
	switch {
	case tsaURL == "" && trustBundlePath == "":
		return nil, nil
	case trustBundlePath == "":
		return nil, errors.New("audit: a TSA URL is set but no TSA trust bundle; tokens are verified before they are stored, so both are required")
	case tsaURL == "":
		return nil, errors.New("audit: a TSA trust bundle is set but no TSA URL")
	}
	u, err := url.Parse(tsaURL)
	if err != nil {
		return nil, fmt.Errorf("audit: TSA URL: %w", err)
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return nil, fmt.Errorf("audit: TSA URL %s must be http or https", u.Redacted())
	}
	if u.Host == "" {
		return nil, fmt.Errorf("audit: TSA URL %s has no host", u.Redacted())
	}
	trust, err := LoadTSATrustBundle(trustBundlePath)
	if err != nil {
		return nil, err
	}
	return newTSAAnchorSink(local, tsaURL, trust, newHTTPTSAPost(nil, tsaURL))
}

// ComposeAnchorSink is the daemon's anchor sink: the local file alone when
// neither external sink is configured (nil), else a TeeSink writing the file
// first, then the bucket, then the TSA.
func ComposeAnchorSink(file *FileSink, bucket *GCSAnchorSink, tsa *TSAAnchorSink) RootSink {
	var externals []RootSink
	if bucket != nil {
		externals = append(externals, bucket)
	}
	if tsa != nil {
		externals = append(externals, tsa)
	}
	if len(externals) == 0 {
		return file
	}
	return NewTeeSink(file, externals...)
}

func newTSAAnchorSink(local *FileSink, tsaURL string, trust *x509.CertPool, post tsaPostFunc) (*TSAAnchorSink, error) {
	if local == nil || trust == nil || post == nil {
		return nil, errors.New("audit: TSA sink needs the local anchor file, a trust bundle and a transport")
	}
	return &TSAAnchorSink{url: redactURL(tsaURL), trust: trust, local: local, dir: TSATokenDir(local.path), post: post}, nil
}

// URI is the TSA, for log lines.
func (s *TSAAnchorSink) URI() string { return s.url }

// TokenDir is where tokens are stored.
func (s *TSAAnchorSink) TokenDir() string { return s.dir }

func (s *TSAAnchorSink) tokenPath(checkpoint int64) string {
	return filepath.Join(s.dir, tsaTokenName(checkpoint))
}

func (s *TSAAnchorSink) PublishRoot(ctx context.Context, checkpoint int64, root string) error {
	digest := AnchorRecordDigest(checkpoint, root)
	path := s.tokenPath(checkpoint)
	existing, err := os.ReadFile(filepath.Clean(path))
	switch {
	case err == nil:
		return s.checkExisting(existing, digest, checkpoint, path)
	case !errors.Is(err, os.ErrNotExist):
		return fmt.Errorf("audit: read timestamp token %s: %w", path, err)
	}

	token, err := s.stamp(ctx, digest)
	if err != nil {
		return err
	}
	if err := writeTokenOnce(s.dir, path, token); err != nil {
		if errors.Is(err, os.ErrExist) {
			if existing, rerr := os.ReadFile(filepath.Clean(path)); rerr == nil {
				return s.checkExisting(existing, digest, checkpoint, path)
			}
		}
		return err
	}
	return nil
}

// checkExisting: a stored token for the same record is an idempotent
// republish; one for a different record is a conflict (RootSink contract).
func (s *TSAAnchorSink) checkExisting(token, digest []byte, checkpoint int64, path string) error {
	_, err := VerifyTSAToken(token, s.trust, digest)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, ErrTSAImprintMismatch):
		return fmt.Errorf("%w: checkpoint=%d (%s)", ErrAnchorConflict, checkpoint, path)
	}
	return fmt.Errorf("audit: stored timestamp token %s does not verify: %w", path, err)
}

// stamp asks the TSA for a token over digest and returns it only once it
// verifies against the trust bundle with the nonce sent.
func (s *TSAAnchorSink) stamp(ctx context.Context, digest []byte) ([]byte, error) {
	var nb [8]byte
	if _, err := rand.Read(nb[:]); err != nil {
		return nil, fmt.Errorf("audit: TSA nonce: %w", err)
	}
	nonce := new(big.Int).SetBytes(nb[:])
	req := timestamp.Request{HashAlgorithm: crypto.SHA256, HashedMessage: digest, Certificates: true, Nonce: nonce}
	body, err := req.Marshal()
	if err != nil {
		return nil, fmt.Errorf("audit: build TSA request: %w", err)
	}
	reply, err := s.post(ctx, body)
	if err != nil {
		return nil, err
	}
	if err := checkStrictDER(reply); err != nil {
		return nil, fmt.Errorf("%w: reply from %s: %v", ErrTSATokenInvalid, s.url, err)
	}
	// ParseResponse turns a non-granted PKIStatus into an error.
	ts, err := recoverParse(func() (*timestamp.Timestamp, error) { return timestamp.ParseResponse(reply) })
	if err != nil {
		if isTSAStatusError(err) {
			return nil, fmt.Errorf("audit: TSA %s refused the request: %v", s.url, err)
		}
		return nil, fmt.Errorf("%w: reply from %s: %v", ErrTSATokenInvalid, s.url, err)
	}
	info, err := VerifyTSAToken(ts.RawToken, s.trust, digest)
	if err != nil {
		return nil, fmt.Errorf("token from %s: %w", s.url, err)
	}
	if info.Nonce == nil || info.Nonce.Cmp(nonce) != 0 {
		return nil, fmt.Errorf("token from %s: %w", s.url, ErrTSANonceMismatch)
	}
	return ts.RawToken, nil
}

// isTSAStatusError: timestamp.ParseResponse reports a non-granted status as
// a plain error starting with the status name.
func isTSAStatusError(err error) bool {
	var pe timestamp.ParseError
	if errors.As(err, &pe) {
		return false
	}
	for _, st := range []timestamp.Status{timestamp.GrantedWithMods, timestamp.Rejection, timestamp.Waiting, timestamp.RevocationWarning, timestamp.RevocationNotification} {
		if strings.HasPrefix(err.Error(), st.String()+":") {
			return true
		}
	}
	return false
}

// writeTokenOnce writes token to path without ever replacing an existing
// file: a temp file in the same directory, then a hard link, which fails if
// path exists. A crash leaves at most a stray temp file, never a partial
// token at path.
func writeTokenOnce(dir, path string, token []byte) error {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("audit: create token directory %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, ".tmp-*.tsr")
	if err != nil {
		return fmt.Errorf("audit: create token temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if _, err := tmp.Write(token); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("audit: write token: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("audit: sync token: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("audit: close token: %w", err)
	}
	if err := os.Link(tmpName, path); err != nil {
		return fmt.Errorf("audit: store token %s: %w", path, err)
	}
	return nil
}

// LastPublished reports the highest checkpoint with a stored token, with the
// local file's root for it. The token must verify against that root: a token
// the local record does not match is an error, never "not anchored".
func (s *TSAAnchorSink) LastPublished(ctx context.Context) (int64, string, bool, error) {
	cps, _, err := listTSATokens(s.dir)
	if err != nil {
		return 0, "", false, err
	}
	if len(cps) == 0 {
		return 0, "", false, nil
	}
	cp := cps[len(cps)-1]
	local, err := s.local.Checkpoints()
	if err != nil {
		return 0, "", false, err
	}
	root, found := "", false
	for _, c := range local {
		if c.Checkpoint == cp {
			root, found = c.Root, true
		}
	}
	if !found {
		return 0, "", false, fmt.Errorf("audit: timestamp token for checkpoint %d has no record in the local anchor file", cp)
	}
	token, err := os.ReadFile(filepath.Clean(s.tokenPath(cp)))
	if err != nil {
		return 0, "", false, fmt.Errorf("audit: read timestamp token: %w", err)
	}
	if _, err := VerifyTSAToken(token, s.trust, AnchorRecordDigest(cp, root)); err != nil {
		return 0, "", false, fmt.Errorf("audit: timestamp token for checkpoint %d: %w", cp, err)
	}
	return cp, root, true, nil
}

// listTSATokens returns the checkpoints with a token file in dir, ascending,
// and the names of other entries. A missing directory is no tokens.
func listTSATokens(dir string) (cps []int64, unrecognised []string, err error) {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, fmt.Errorf("audit: list timestamp tokens in %s: %w", dir, err)
	}
	for _, e := range entries {
		name := e.Name()
		if strings.HasPrefix(name, ".tmp-") {
			continue // a write interrupted before the link
		}
		base, ok := strings.CutSuffix(name, ".tsr")
		cp, perr := strconv.ParseInt(base, 10, 64)
		if !ok || !e.Type().IsRegular() || perr != nil || cp < 0 || tsaTokenName(cp) != name {
			unrecognised = append(unrecognised, name)
			continue
		}
		cps = append(cps, cp)
	}
	sort.Slice(cps, func(i, j int) bool { return cps[i] < cps[j] })
	return cps, unrecognised, nil
}
