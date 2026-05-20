package wake

import "os"

// osGetenv is a tiny indirection so the trusted-proxies test can
// stub the env-var read without globally clobbering os.Getenv.
func osGetenv(key string) string {
	return os.Getenv(key)
}
