//go:build windows

package audit

// tokenOpenNonBlock is 0 on Windows, which has no FIFOs at a file path.
const tokenOpenNonBlock = 0
