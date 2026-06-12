//go:build !linux

package waf

func isLinux() bool { return false }
