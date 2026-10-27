//go:build !windows

package audit

import "syscall"

// tokenOpenNonBlock keeps an open of a FIFO swapped in at a token path from
// blocking; it has no effect on a regular file.
const tokenOpenNonBlock = syscall.O_NONBLOCK
