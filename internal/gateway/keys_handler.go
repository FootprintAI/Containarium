package gateway

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/footprintai/containarium/pkg/core/container"
)

// UserKeys holds a username and their authorized_keys content.
type UserKeys struct {
	Username       string `json:"username"`
	AuthorizedKeys string `json:"authorized_keys"`
}

// KeysResponse is the JSON response from the /authorized-keys endpoint.
type KeysResponse struct {
	Keys []UserKeys `json:"keys"`
}

// SentinelKeyRequest is the JSON body for POST /authorized-keys/sentinel.
type SentinelKeyRequest struct {
	PublicKey string `json:"public_key"`
}

// ServeAuthorizedKeys returns an HTTP handler that walks
// homeRoot/*/.ssh/authorized_keys and returns each user's authorized keys
// as JSON for the sentinel to sync into sshpiper.
//
// homeRoot defaults to "/home" when empty (allows tests to inject a
// tmp dir).
//
// containerExistsFn is the orphan filter for #343: when non-nil, each
// candidate username is checked against the live container registry,
// and entries whose container is missing are dropped from the response
// AND logged as `WARNING orphan ...`. This prevents sshpiper from
// accepting keys for tenants whose container has been deleted (the
// resulting "Container <name>-container not found" inside the SSH
// session was the user-facing symptom in #343). Pass nil to disable
// the filter (back-compat / tests).
func ServeAuthorizedKeys(homeRoot string, containerExistsFn func(username string) bool) http.HandlerFunc {
	if homeRoot == "" {
		homeRoot = "/home"
	}
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
			return
		}

		entries, err := os.ReadDir(homeRoot)
		if err != nil {
			log.Printf("[keys] failed to read %s: %v", homeRoot, err)
			http.Error(w, `{"error":"failed to read home directories"}`, http.StatusInternalServerError)
			return
		}

		var keys []UserKeys
		orphanCount := 0
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			username := entry.Name()
			akPath := filepath.Join(homeRoot, username, ".ssh", "authorized_keys")
			// akPath is built from os.ReadDir output (entry.Name() has
			// no path separators) joined with a fixed suffix — caller
			// can't inject a traversal.
			// #nosec G304 -- safe path construction (see above)
			data, err := os.ReadFile(akPath)
			if err != nil {
				continue // no authorized_keys file, skip
			}
			content := strings.TrimSpace(string(data))
			if content == "" {
				continue
			}
			if containerExistsFn != nil && !containerExistsFn(username) {
				// Only count/warn about accounts the orphan-reaper will
				// actually touch. reapOnce (orphan_reaper.go) refuses to
				// delete anything whose login shell isn't the
				// containarium-managed wrapper — a real host admin login
				// (e.g. the VM's own cloud-init "ubuntu" user) can share
				// this directory shape without ever being reap-eligible.
				// Without this gate the WARNING claims "orphan-reaper will
				// clean up on next tick" forever for an account the reaper
				// will never touch.
				if shell, shellErr := container.UserLoginShell(username); shellErr == nil && container.IsContainerManagedShell(shell) {
					orphanCount++
				}
				continue
			}
			keys = append(keys, UserKeys{
				Username:       username,
				AuthorizedKeys: content,
			})
		}
		if orphanCount > 0 {
			log.Printf("[keys] WARNING: %d orphan authorized_keys found (no live container); orphan-reaper will clean up on next tick", orphanCount)
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(KeysResponse{Keys: keys})
	}
}

// sentinelKeyMarker is the comment line that flags the next line as the
// sentinel's current upstream pubkey in a user's authorized_keys file.
// applySentinelKey uses this marker to find and replace stale entries on
// rotation (sentinel VM replacement → new upstream keypair → old marker
// block must go, new one must take its place).
const sentinelKeyMarker = "# sshpiper sentinel upstream key"

// ServeSentinelKey returns an HTTP handler that accepts a POST with the
// sentinel's current upstream public key and installs it in every jump
// server user's authorized_keys file. Replaces any prior sentinel-marker
// block so that rotating the sentinel doesn't leave containers stranded
// with the old upstream key.
func ServeSentinelKey() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
			return
		}

		var req SentinelKeyRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, `{"error":"invalid JSON body"}`, http.StatusBadRequest)
			return
		}

		pubKey := strings.TrimSpace(req.PublicKey)
		if pubKey == "" {
			http.Error(w, `{"error":"public_key is required"}`, http.StatusBadRequest)
			return
		}

		updated, rotated, err := applySentinelKey("/home", pubKey)
		if err != nil {
			log.Printf("[keys] sentinel-key apply failed: %v", err)
			http.Error(w, `{"error":"failed to apply sentinel key"}`, http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]int{
			"updated": updated,
			"rotated": rotated,
		})
	}
}

// applySentinelKey rewrites every user's authorized_keys under homeRoot so
// the current sentinel upstream pubkey is installed exactly once, replacing
// any prior sentinel-marker block.
//
// Returns:
//
//   - updated: number of users whose authorized_keys now contains pubKey
//     (includes both first-install and rotation cases).
//   - rotated: number of users where a *different* prior sentinel key was
//     replaced. Useful for observability of rotation events.
func applySentinelKey(homeRoot, pubKey string) (updated, rotated int, err error) {
	entries, err := os.ReadDir(homeRoot)
	if err != nil {
		return 0, 0, fmt.Errorf("read %s: %w", homeRoot, err)
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		username := entry.Name()
		sshDir := filepath.Join(homeRoot, username, ".ssh")
		if _, statErr := os.Stat(sshDir); os.IsNotExist(statErr) {
			continue
		}

		akPath := filepath.Join(sshDir, "authorized_keys")
		// akPath is built from os.ReadDir output ("entry.Name()" is a
		// directory base name with no path separators) joined with a
		// fixed ".ssh/authorized_keys" suffix. Caller cannot inject a
		// traversal here; akPath always lands inside homeRoot.
		// #nosec G304 -- safe path construction (see above)
		existing, _ := os.ReadFile(akPath)

		newContent, hadPriorKey, priorKeyDiffers := rewriteSentinelBlock(string(existing), pubKey)
		if newContent == string(existing) {
			// Already in the desired shape; count as updated since the
			// key IS present.
			updated++
			continue
		}

		if writeErr := writeAuthorizedKeys(akPath, sshDir, newContent); writeErr != nil {
			log.Printf("[keys] failed to write %s: %v", akPath, writeErr)
			continue
		}

		updated++
		if hadPriorKey && priorKeyDiffers {
			rotated++
			log.Printf("[keys] rotated sentinel key in %s", akPath)
		} else {
			log.Printf("[keys] added sentinel key to %s", akPath)
		}
	}
	return updated, rotated, nil
}

// sshKeyMaterial returns the "<type> <base64>" prefix of an authorized_keys
// line, ignoring any trailing comment, and true when the line looks like a
// public key. Two lines name the same key iff their material matches — the
// comment field is cosmetic and must not defeat dedup.
//
// Sentinel upstream keys are written without an options prefix, so the type
// is the first whitespace field; option-prefixed lines (which a sentinel key
// never is) return false and are left untouched.
func sshKeyMaterial(line string) (string, bool) {
	f := strings.Fields(strings.TrimSpace(line))
	if len(f) < 2 {
		return "", false
	}
	switch {
	case strings.HasPrefix(f[0], "ssh-"),
		strings.HasPrefix(f[0], "ecdsa-"),
		strings.HasPrefix(f[0], "sk-"):
		return f[0] + " " + f[1], true
	default:
		return "", false
	}
}

// rewriteSentinelBlock returns authorized_keys content with the sentinel
// marker + one current pubKey, replacing any prior sentinel marker block
// (and the key line that follows it).
//
// It also absorbs any *unmarked* stray copy of the current sentinel key: an
// older seeding path or a manual injection can leave the upstream key in the
// file without the marker, which the marker scan alone would never reconcile,
// so it accumulates across rotations. Dropping every line whose key material
// equals pubKey (regardless of marker or comment) guarantees the canonical
// block appended below is the sole occurrence.
//
// Returns the new content, whether a prior sentinel block existed, and
// whether the prior key (if any) differed from pubKey.
func rewriteSentinelBlock(existing, pubKey string) (newContent string, hadPrior, priorDiffers bool) {
	lines := strings.Split(existing, "\n")
	out := make([]string, 0, len(lines)+2)
	targetMat, haveTarget := sshKeyMaterial(pubKey)

	// Drop every "marker + next-non-empty-line" pair from the input, plus
	// any stray (unmarked) copy of the current sentinel key.
	for i := 0; i < len(lines); i++ {
		line := lines[i]
		if strings.TrimSpace(line) == sentinelKeyMarker {
			hadPrior = true
			// Find the next non-empty line — that's the prior key.
			j := i + 1
			for j < len(lines) && strings.TrimSpace(lines[j]) == "" {
				j++
			}
			if j < len(lines) {
				prior := strings.TrimSpace(lines[j])
				// Compare by key material so a comment-only difference on
				// the same key is not mistaken for a rotation.
				if pm, ok := sshKeyMaterial(prior); !ok || !haveTarget || pm != targetMat {
					priorDiffers = true
				}
				i = j // skip the prior key line as well
			}
			continue
		}
		// Silently dedup an unmarked copy of the current key; the canonical
		// block re-adds it once below.
		if haveTarget {
			if m, ok := sshKeyMaterial(line); ok && m == targetMat {
				continue
			}
		}
		out = append(out, line)
	}

	// Trim trailing empty lines for a clean append.
	for len(out) > 0 && strings.TrimSpace(out[len(out)-1]) == "" {
		out = out[:len(out)-1]
	}

	// Now append the canonical block.
	out = append(out, "", sentinelKeyMarker, pubKey, "")

	return strings.Join(out, "\n"), hadPrior, priorDiffers
}

// writeAuthorizedKeys writes content to akPath with mode 0600 and tries
// to set ownership to match sshDir's owner. Writes via temp file + rename
// so a partial write can't corrupt the file.
func writeAuthorizedKeys(akPath, sshDir, content string) error {
	tmp := akPath + ".tmp"
	if err := os.WriteFile(tmp, []byte(content), 0600); err != nil {
		return err
	}

	if info, statErr := os.Stat(sshDir); statErr == nil {
		if stat, ok := fileOwner(info); ok {
			_ = os.Chown(tmp, stat.uid, stat.gid)
		}
	}

	return os.Rename(tmp, akPath)
}
