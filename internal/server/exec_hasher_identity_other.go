//go:build !linux && !darwin

package server

import "os"

// exeIdentityOf has no file identity to key on here: nothing is cached.
func exeIdentityOf(os.FileInfo) (exeIdentity, bool) { return exeIdentity{}, false }
