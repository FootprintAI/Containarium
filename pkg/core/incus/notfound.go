package incus

import (
	"net/http"

	"github.com/lxc/incus/v7/shared/api"
)

// IsNotFound reports whether err is the backend answering "no such object"
// rather than failing.
//
// It exists so callers outside this package can tell "the box is not there" from
// "the lookup broke" without importing the Incus SDK themselves — the server
// layer deliberately depends on this package's own types, not on
// github.com/lxc/incus (see box.BoxStatus's doc comment). Client.GetContainer and
// friends wrap the backend error with %w, so the status check still reaches
// through the wrap.
func IsNotFound(err error) bool {
	return err != nil && api.StatusErrorCheck(err, http.StatusNotFound)
}
