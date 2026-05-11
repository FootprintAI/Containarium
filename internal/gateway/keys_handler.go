package gateway

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
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

// ServeAuthorizedKeys returns an HTTP handler that walks /home/*/.ssh/authorized_keys
// and returns all users' authorized keys as JSON. This allows the sentinel to sync
// SSH keys for sshpiper configuration.
func ServeAuthorizedKeys() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
			return
		}

		entries, err := os.ReadDir("/home")
		if err != nil {
			log.Printf("[keys] failed to read /home: %v", err)
			http.Error(w, `{"error":"failed to read home directories"}`, http.StatusInternalServerError)
			return
		}

		var keys []UserKeys
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			username := entry.Name()
			akPath := filepath.Join("/home", username, ".ssh", "authorized_keys")
			data, err := os.ReadFile(akPath)
			if err != nil {
				continue // no authorized_keys file, skip
			}
			content := strings.TrimSpace(string(data))
			if content == "" {
				continue
			}
			keys = append(keys, UserKeys{
				Username:       username,
				AuthorizedKeys: content,
			})
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(KeysResponse{Keys: keys})
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
		json.NewEncoder(w).Encode(map[string]int{
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

// rewriteSentinelBlock returns authorized_keys content with the sentinel
// marker + one current pubKey, replacing any prior sentinel marker block
// (and the key line that follows it).
//
// Returns the new content, whether a prior sentinel block existed, and
// whether the prior key (if any) differed from pubKey.
func rewriteSentinelBlock(existing, pubKey string) (newContent string, hadPrior, priorDiffers bool) {
	lines := strings.Split(existing, "\n")
	out := make([]string, 0, len(lines)+2)

	// Drop every "marker + next-non-empty-line" pair from the input.
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
				if prior != pubKey {
					priorDiffers = true
				}
				i = j // skip the prior key line as well
			}
			continue
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
