package container

import (
	"fmt"
	"os/user"
	"strconv"
)

// userSSHOwner resolves the uid/gid that own a jump account's files. A var so
// tests, which have no such host user, can stub it.
var userSSHOwner = func(username string) (uid, gid int, err error) {
	u, err := user.Lookup(username)
	if err != nil {
		return 0, 0, fmt.Errorf("lookup user %q: %w", username, err)
	}
	uid, err = strconv.Atoi(u.Uid)
	if err != nil {
		return 0, 0, fmt.Errorf("parse uid %q: %w", u.Uid, err)
	}
	gid, err = strconv.Atoi(u.Gid)
	if err != nil {
		return 0, 0, fmt.Errorf("parse gid %q: %w", u.Gid, err)
	}
	return uid, gid, nil
}
