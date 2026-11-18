#!/usr/bin/env bash
# Source policy for the binary an installer copies in as root (#3681).
#
# binary_src_check <path> <operator-uid> returns 0 only when <path> is a
# regular file (not a symlink) owned by root or by <operator-uid>. Otherwise it
# prints why, naming the path and the owner it found, and returns 1. There is
# no bypass: a file planted in a shared directory such as /tmp by another user
# must not be installed as root.
#
# scripts/lib/deploy-install.sh embeds this function in the command it sends to
# the host (via `declare -f`), so it must stay POSIX-simple and self-contained.
binary_src_check() {
    local path="$1" op="$2" owner
    if [ -L "$path" ]; then
        echo "Error: refusing binary source $path: it is a symlink" >&2
        return 1
    fi
    if [ ! -f "$path" ]; then
        echo "Error: refusing binary source $path: not a regular file" >&2
        return 1
    fi
    owner="$(stat -c %u "$path" 2>/dev/null)" || {
        echo "Error: refusing binary source $path: cannot read its owner" >&2
        return 1
    }
    if [ "$owner" != 0 ] && [ "$owner" != "$op" ]; then
        echo "Error: refusing binary source $path: owned by uid $owner, not root or the invoking operator (uid $op)" >&2
        return 1
    fi
}
