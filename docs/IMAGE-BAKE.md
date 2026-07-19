# Baked base images

`containarium image-bake` (#1037, v0.56.0) runs the per-create provisioning
(package repos, podman, service enablement) once into a local Incus image.
Stackless creates whose source image + podman setting match the bake's
recorded properties clone the baked image and skip the in-container package
install — measured on a production backend: **~190s → ~72s per create**, and
no mid-create exposure to distro/mirror outages.

## One-time bake

```sh
sudo containarium image-bake                    # defaults: images:ubuntu/24.04, podman on
sudo containarium image-bake --image images:ubuntu/22.04
```

The bake publishes a local image alias (`containarium-base-<image>`); creates
pick it up automatically when it matches. No baked image = the previous
full-provisioning behavior, unchanged. To disable the fast path:

```sh
incus image alias delete containarium-base-images-ubuntu-24-04
```

## Scheduled re-bake (recommended)

A create from a baked image never re-runs the package install, so **only
re-baking picks up security updates**. Ship the weekly timer:

| File | Purpose |
| --- | --- |
| `scripts/containarium-rebake.service` | one re-bake run (`image-bake`, ~3-5 min) |
| `scripts/containarium-rebake.timer` | fires it Sunday 03:30 (+ up to 30 min jitter), catches up after downtime |

```sh
sudo cp scripts/containarium-rebake.service scripts/containarium-rebake.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now containarium-rebake.timer

# verify
systemctl list-timers containarium-rebake.timer
journalctl -u containarium-rebake -n 20      # after the first run
```

Non-default bakes: put flags in `/etc/containarium/rebake.env`, e.g.
`REBAKE_FLAGS=--image images:ubuntu/22.04 --podman=true`.

A failed re-bake (mirrors down, host wedged) is safe: the alias only moves on
a successful publish, so creates keep using the previous bake. Check
`systemctl status containarium-rebake` if `containarium.baked_at` (visible
via `incus image show <alias>`) grows older than a week.
