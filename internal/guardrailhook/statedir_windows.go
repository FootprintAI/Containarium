//go:build windows

package guardrailhook

import "os"

// checkPrivateDir has nothing to check here: permission bits and a numeric
// owner are not how access to a directory is expressed on this platform.
func checkPrivateDir(string, os.FileInfo) error { return nil }
