package audit

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
)

// #2728: check the local anchor file and the database against the TSA
// tokens stored next to the file.
//
// The tokens live on the same host as the file, so a host-root attacker can
// delete them; what they cannot do is make a token vouch for an edited
// record, because the token is signed by the TSA over the record's hash.
// Hence: a token that does not verify, or covers a different record than the
// local line, is a failure; a local checkpoint with no token is only a
// warning (Q6).

// TSAFindingKind classifies one result of VerifyAnchorsAgainstTSA.
type TSAFindingKind int

const (
	TSAFindingUnspecified TSAFindingKind = iota

	// Failures.

	// TSAFindingTokenInvalid: a token is malformed, its signature does not
	// verify, or it carries no TSA certificate.
	TSAFindingTokenInvalid
	// TSAFindingUntrustedSigner: a token is not signed by a TSA chaining to
	// the trust bundle at the token's genTime.
	TSAFindingUntrustedSigner
	// TSAFindingImprintMismatch: a valid token covers a different record than
	// the local anchor file holds for its checkpoint: the line was edited.
	TSAFindingImprintMismatch
	// TSAFindingMissingLocally: a token exists for a checkpoint the local file
	// lacks. The daemon writes the file first, so a line was removed.
	TSAFindingMissingLocally
	// TSAFindingDatabaseRootDiffers: the database row at an anchored
	// checkpoint no longer hashes to the anchored root, or no longer exists.
	TSAFindingDatabaseRootDiffers

	// Warnings.

	// TSAFindingNoToken: local checkpoints have no token (anchored before the
	// TSA was configured, or a stamp that has not succeeded yet).
	TSAFindingNoToken
	// TSAFindingUnrecognisedFile: a file in the token directory is not named
	// like a token. Never counted as one.
	TSAFindingUnrecognisedFile
	// TSAFindingBelowChainBase: anchored checkpoints lie below the chain base
	// (rows purged by retention, #2878); their tokens are checked against the
	// local file, not the database.
	TSAFindingBelowChainBase
)

func (k TSAFindingKind) String() string {
	switch k {
	case TSAFindingTokenInvalid:
		return "token-invalid"
	case TSAFindingUntrustedSigner:
		return "untrusted-signer"
	case TSAFindingImprintMismatch:
		return "imprint-mismatch"
	case TSAFindingMissingLocally:
		return "missing-locally"
	case TSAFindingDatabaseRootDiffers:
		return "database-root-differs"
	case TSAFindingNoToken:
		return "no-token"
	case TSAFindingUnrecognisedFile:
		return "unrecognised-file"
	case TSAFindingBelowChainBase:
		return "below-chain-base"
	}
	return "unspecified"
}

// TSAAnchorFinding is one failure or warning. Checkpoint is 0 when the
// finding is not about one checkpoint.
type TSAAnchorFinding struct {
	Kind       TSAFindingKind
	Checkpoint int64
	Detail     string
	// Err is the verification error behind a token failure, for errors.Is
	// (ErrTSANotStrictDER, ErrTSATokenTooLarge, ...); nil otherwise.
	Err error
}

// TSAAnchorReport is the result of VerifyAnchorsAgainstTSA. Failures make
// verify-anchor exit non-zero; Warnings do not.
type TSAAnchorReport struct {
	Failures []TSAAnchorFinding
	Warnings []TSAAnchorFinding
	// StampedCheckpoints counts the local checkpoints whose token verified
	// and matches the local record; LatestStamped is the highest of them.
	StampedCheckpoints int
	LatestStamped      int64
	// TailCheckpoint and TailRoot are the highest local checkpoint at or
	// below the database's highest row id: where the chain-consistency check
	// of the rows logged after it starts.
	TailCheckpoint int64
	TailRoot       string
	// BelowChainBase counts anchored checkpoints below the chain base.
	BelowChainBase int
}

// OK reports whether there are no failures.
func (r TSAAnchorReport) OK() bool { return len(r.Failures) == 0 }

// VerifyAnchorsAgainstTSA checks every token in the local file's token
// directory against the trust bundle and the local record for its
// checkpoint, and every local checkpoint against the database. ErrNoAnchor
// means neither the file nor the token directory holds anything.
func VerifyAnchorsAgainstTSA(ctx context.Context, chain ChainStore, local *FileSink, trust *x509.CertPool) (TSAAnchorReport, error) {
	var r TSAAnchorReport
	dir := TSATokenDir(local.path)
	tokenCPs, unrecognised, err := listTSATokens(dir)
	if err != nil {
		return r, err
	}
	localCPs, err := local.Checkpoints()
	if err != nil {
		return r, err
	}
	if len(tokenCPs) == 0 && len(localCPs) == 0 {
		return r, ErrNoAnchor
	}
	maxID, err := chain.MaxRowID(ctx)
	if err != nil {
		return r, fmt.Errorf("audit: max row id: %w", err)
	}
	var base ChainBase
	var purged bool
	if br, ok := chain.(ChainBaseReader); ok {
		if base, purged, err = br.ChainBase(ctx); err != nil {
			return r, err
		}
	}
	belowBase := func(cp int64) bool { return purged && cp < base.ID }

	localRoots := make(map[int64][]string, len(localCPs))
	for _, c := range localCPs {
		localRoots[c.Checkpoint] = append(localRoots[c.Checkpoint], c.Root)
	}

	for _, name := range unrecognised {
		r.Warnings = append(r.Warnings, TSAAnchorFinding{Kind: TSAFindingUnrecognisedFile,
			Detail: fmt.Sprintf("%s is not named like a timestamp token and is ignored", filepath.Join(dir, name))})
	}

	stamped := make(map[int64]bool, len(tokenCPs))
	for _, cp := range tokenCPs {
		roots := localRoots[cp]
		if len(roots) == 0 {
			r.Failures = append(r.Failures, TSAAnchorFinding{Kind: TSAFindingMissingLocally, Checkpoint: cp,
				Detail: "a timestamp token exists for this checkpoint but the local anchor file has no record of it"})
			continue
		}
		token, err := readTokenFile(filepath.Join(dir, tsaTokenName(cp)))
		switch {
		case errors.Is(err, ErrTSATokenInvalid):
			// Oversized, or swapped for a non-regular file after listing.
			r.Failures = append(r.Failures, TSAAnchorFinding{Kind: TSAFindingTokenInvalid, Checkpoint: cp, Detail: err.Error(), Err: err})
			continue
		case err != nil:
			return r, fmt.Errorf("audit: read timestamp token for checkpoint %d: %w", cp, err)
		}
		info, err := verifyTSATokenSignature(token, trust)
		switch {
		case errors.Is(err, ErrTSAUntrustedSigner):
			r.Failures = append(r.Failures, TSAAnchorFinding{Kind: TSAFindingUntrustedSigner, Checkpoint: cp, Detail: err.Error(), Err: err})
			continue
		case err != nil:
			r.Failures = append(r.Failures, TSAAnchorFinding{Kind: TSAFindingTokenInvalid, Checkpoint: cp, Detail: err.Error(), Err: err})
			continue
		}
		matches := true
		for _, root := range roots {
			if string(AnchorRecordDigest(cp, root)) != string(info.Imprint) {
				matches = false
			}
		}
		if !matches {
			r.Failures = append(r.Failures, TSAAnchorFinding{Kind: TSAFindingImprintMismatch, Checkpoint: cp,
				Detail: fmt.Sprintf("the local anchor file's record differs from the one the TSA stamped at %s: the line was edited after anchoring", info.GenTime.UTC().Format("2006-01-02T15:04:05Z"))})
			continue
		}
		stamped[cp] = true
		r.StampedCheckpoints++
		if cp > r.LatestStamped {
			r.LatestStamped = cp
		}
	}

	// Every local checkpoint is compared with the database, stamped or not,
	// so turning the TSA on never weakens the local-file check.
	cps := make([]int64, 0, len(localRoots))
	for cp := range localRoots {
		cps = append(cps, cp)
	}
	sort.Slice(cps, func(i, j int) bool { return cps[i] < cps[j] })
	var unstamped []int64
	below := 0
	for _, cp := range cps {
		if !stamped[cp] && !containsInt64(tokenCPs, cp) {
			unstamped = append(unstamped, cp)
		}
		if belowBase(cp) {
			below++
			continue
		}
		dbRoot, found, err := chain.RowHashAt(ctx, cp)
		if err != nil {
			return r, fmt.Errorf("audit: row hash at anchored checkpoint %d: %w", cp, err)
		}
		switch {
		case cp > maxID || !found:
			r.Failures = append(r.Failures, TSAAnchorFinding{Kind: TSAFindingDatabaseRootDiffers, Checkpoint: cp,
				Detail: "the anchored row no longer exists in the database"})
		case rootsDiffer(localRoots[cp], dbRoot):
			r.Failures = append(r.Failures, TSAAnchorFinding{Kind: TSAFindingDatabaseRootDiffers, Checkpoint: cp,
				Detail: "the database row's hash differs from the anchored root"})
		}
		if cp <= maxID && cp > r.TailCheckpoint {
			r.TailCheckpoint, r.TailRoot = cp, localRoots[cp][0]
		}
	}
	if n := len(unstamped); n > 0 {
		r.Warnings = append(r.Warnings, TSAAnchorFinding{Kind: TSAFindingNoToken, Checkpoint: unstamped[n-1],
			Detail: fmt.Sprintf("%d local checkpoint(s) have no timestamp token (anchored before the TSA was configured, or a stamp that has not succeeded yet; it is retried on the next anchoring tick). They were checked against the database only", n)})
	}
	if r.BelowChainBase = below; below > 0 {
		r.Warnings = append(r.Warnings, TSAAnchorFinding{Kind: TSAFindingBelowChainBase,
			Detail: fmt.Sprintf("%d anchored checkpoint(s) lie below the chain base id=%d (rows purged by retention); their tokens are checked against the local file, not the database", below, base.ID)})
	}
	return r, nil
}

func containsInt64(s []int64, v int64) bool {
	i := sort.Search(len(s), func(i int) bool { return s[i] >= v })
	return i < len(s) && s[i] == v
}
