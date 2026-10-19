package sshconfig

import (
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
)

// RotateIdentity prepares an existing managed configuration for a new key.
// The caller writes it only after the server accepts the registration.
func RotateIdentity(content, identityFile string) (Generated, error) {
	if identityFile == "" || strings.ContainsAny(identityFile, "\r\n\x00") {
		return Generated{}, fmt.Errorf("invalid SSH identity path")
	}
	// OpenSSH expands percent tokens even inside quotes. Paths may contain
	// spaces or percent signs, and Windows accepts forward slashes.
	identity := strconv.Quote(strings.ReplaceAll(filepath.ToSlash(identityFile), "%", "%%"))
	var out strings.Builder
	g := Generated{}
	inside, began, ended := false, false, false
	for _, line := range strings.SplitAfter(content, "\n") {
		switch strings.TrimSpace(line) {
		case beginMarker:
			if began {
				return Generated{}, fmt.Errorf("duplicate managed SSH configuration")
			}
			inside, began = true, true
		case endMarker:
			if !inside {
				return Generated{}, fmt.Errorf("invalid managed SSH configuration markers")
			}
			inside, ended = false, true
		}
		if inside {
			fields := strings.Fields(line)
			if len(fields) > 0 {
				switch strings.ToLower(fields[0]) {
				case "identityfile":
					continue
				case "match":
					return Generated{}, fmt.Errorf("managed SSH configuration contains a Match block; re-run containarium ssh-config sync")
				case "host":
					out.WriteString(line)
					fmt.Fprintf(&out, "    IdentityFile %s\n", identity)
					g.Count++
					continue
				}
			}
		}
		out.WriteString(line)
	}
	if !began || !ended || g.Count == 0 {
		return Generated{}, fmt.Errorf("no complete managed SSH hosts to rotate; run containarium ssh-config sync first")
	}
	g.Content = out.String()
	return g, nil
}
