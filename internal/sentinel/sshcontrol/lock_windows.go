package sshcontrol

import (
	"errors"
	"os"
)

// lockState rejects the Unix-only local SSH enforcement service on Windows.
func lockState(string) (*os.File, error) {
	return nil, errors.New("SSH upstream control requires Unix file locking")
}
