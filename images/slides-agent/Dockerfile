# containarium-slides-agent
#
# The prebaked image the `slides-agent` recipe (pkg/core/recipes/recipes.yaml,
# #3434) runs inside a box via podman: Node, the open-slide slide framework
# (MIT) built from a pinned commit with its dependencies installed, a headless
# Chromium with the `slides-print-pdf <site> <out.pdf>` entrypoint that prints
# a built site to PDF, the Caddy auth proxy that fronts the dev server, and
# the in-box login helper behind the proxy's zero-click login (#3486).
# Everything a box needs at start is in here, so starting a box fetches
# nothing from a package registry; the image pull is the only fetch.
#
# Layout inside the image:
#   /opt/open-slide/app         upstream's `demo` workspace package deployed with
#                               its production dependencies from the monorepo
#                               lockfile (core built from the pinned commit); the
#                               dev server's cwd, open-slide.config.ts replaced
#   /opt/open-slide/template    the scaffold's deck tree + agent files, seeded
#                               into the bind-mounted /workspace on first start
#   /workspace                  bind mount: the deck tree on the box disk
#   /etc/caddy/Caddyfile        the auth proxy (images/slides-agent/Caddyfile)
#   /usr/local/bin/slides-wsauth the login helper (images/slides-agent/wsauth)
#
# Upstream open-slide is data: it is fetched by commit, the checkout is verified
# against the pin, its lockfile decides its dependency set, and no dependency
# lifecycle script runs. The only upstream code that executes at build time is
# the framework's own TypeScript build.
#
# Publishing follows the sidecar images (ghcr.io/footprintai/containarium-<name>:vX.Y.Z,
# tag = the Containarium release; docs/PLATFORM-SIDECAR-DESIGN.md decision #4).
# Build context is the repo root:
#   docker build -f images/slides-agent/Dockerfile -t containarium-slides-agent .

ARG NODE_IMAGE=docker.io/library/node:22.23.4-bookworm-slim
ARG GO_IMAGE=docker.io/library/golang:1.26.10-bookworm

# --- the proxy binary -------------------------------------------------------
# Caddy is built from source rather than copied from the upstream image: the
# upstream binary is compiled with a Go toolchain and module set that carry
# fixed HIGH findings (stdlib, x/net, go-jose), which the image's blocking
# Trivy gate refuses. Same approach as `make build-caddy`: the checksum-pinned
# xcaddy installer the repo already uses, the Go version the other images
# build with, the Caddy release pinned here, and the two dependency bumps the
# findings name. Bump CADDY_VERSION and drop a --replace when upstream catches up.
FROM ${GO_IMAGE} AS caddy
ARG CADDY_VERSION=v2.11.7
WORKDIR /src
COPY scripts/install-xcaddy.sh scripts/xcaddy-version.env scripts/
RUN scripts/install-xcaddy.sh /usr/local/bin/xcaddy \
    && CGO_ENABLED=0 xcaddy build "${CADDY_VERSION}" \
         --replace golang.org/x/net=golang.org/x/net@v0.60.0 \
         --replace github.com/go-jose/go-jose/v4=github.com/go-jose/go-jose/v4@v4.1.6 \
         --output /out/caddy \
    && /out/caddy version \
    # Only /out/caddy leaves this stage; drop the module and build caches so
    # the layer stays small.
    && rm -rf /root/.cache /go/pkg/mod /tmp/*

# --- the login helper ---------------------------------------------------------
# Go standard library only, built on the same pinned Go image as Caddy. Only the
# non-test sources are copied, into a module of their own, so the build needs
# nothing but the toolchain.
FROM ${GO_IMAGE} AS wsauth
WORKDIR /src
COPY images/slides-agent/wsauth/main.go images/slides-agent/wsauth/wsauth.go ./
RUN go mod init slides-wsauth \
    && CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/slides-wsauth . \
    && rm -rf /root/.cache /tmp/*

# --- build open-slide from the pinned commit ---------------------------------
FROM ${NODE_IMAGE} AS build
ARG OPEN_SLIDE_REPO=https://github.com/open-slide/open-slide
# open-slide/open-slide at this commit is MIT licensed; bump deliberately and
# re-check the licence and the dev server's request guard when you do.
ARG OPEN_SLIDE_COMMIT=1ce6bd5268efeaf4cc3bed28112ac770fc5f3b34
# The version the repo's own package.json names as its packageManager.
ARG PNPM_VERSION=10.17.0

RUN apt-get update \
    && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && npm install -g "pnpm@${PNPM_VERSION}"

WORKDIR /opt/open-slide/src
# Fetch exactly the pinned commit and verify the checkout is that commit.
RUN git init -q . \
    && git remote add origin "${OPEN_SLIDE_REPO}" \
    && git fetch -q --depth 1 origin "${OPEN_SLIDE_COMMIT}" \
    && git checkout -q --detach FETCH_HEAD \
    && test "$(git rev-parse HEAD)" = "${OPEN_SLIDE_COMMIT}" \
    && git rev-parse HEAD > /opt/open-slide/COMMIT \
    && rm -rf .git

# Two workspace packages from the monorepo's lockfile: the core package and
# the `demo` app, whose only runtime dependencies are core (a workspace link)
# and react/react-dom. The install carries the dev dependencies the core build
# needs; `pnpm deploy --prod` then materialises the demo app with only its
# production dependencies, resolved from the same lockfile, at
# /opt/open-slide/app, which becomes the dev server's cwd (its example decks
# are not served: open-slide.config.ts points at /workspace). --ignore-scripts:
# no dependency lifecycle scripts (pnpm 10 already blocks them by default).
# CI=1: pnpm refuses some node_modules operations without a TTY otherwise.
RUN pnpm install --frozen-lockfile --ignore-scripts --filter @open-slide/core --filter demo \
    && pnpm --filter @open-slide/core run build \
    && CI=1 pnpm --filter demo deploy --prod --legacy --ignore-scripts /opt/open-slide/app \
    && test -f /opt/open-slide/app/node_modules/@open-slide/core/bin.js \
    && test -f /opt/open-slide/app/node_modules/@open-slide/core/dist/cli/bin.js \
    && test ! -e /opt/open-slide/app/node_modules/@anthropic-ai \
    && test ! -e /opt/open-slide/app/node_modules/@openai

# Core depends on `shadcn` (the component scaffolding CLI) only for its
# stylesheet (`@import 'shadcn/tailwind.css'` in src/app/styles.css, the
# package's dist/tailwind.css); the
# CLI's own server-side dependency tree (express, undici, dotenvx,
# systeminformation) is never imported by dev, build, preview or the printer,
# and carries fixed HIGH findings the image's blocking Trivy gate refuses. That
# tree is removed from the deployed app; the package and its stylesheet stay.
# The offline smoke test on the PR exercises dev, build and print afterwards.
RUN cd /opt/open-slide/app/node_modules \
    && rm -rf .pnpm/express@* .pnpm/express-rate-limit@* .pnpm/body-parser@* \
         .pnpm/undici@* .pnpm/@dotenvx+dotenvx@* .pnpm/systeminformation@* \
    && ! ls .pnpm | grep -E '^(undici|express|body-parser|systeminformation)@' \
    && test -n "$(find .pnpm -path '*/node_modules/shadcn/dist/tailwind.css' -print -quit)" \
    && node -e "require.resolve('/opt/open-slide/app/node_modules/@open-slide/core/package.json')"

# The seed template: the scaffold's deck tree and agent files, which the
# entrypoint copies into the bind-mounted /workspace on first start. The
# template's .claude/skills are relative symlinks into .agents/skills, which
# upstream generates from the core package's skills directory. Nothing else of
# the checkout is kept.
RUN mkdir -p /opt/open-slide/template/.agents \
    && cd /opt/open-slide/src/packages/cli/template \
    && for e in slides themes assets AGENTS.md CLAUDE.md README.md .claude; do \
         [ -e "$e" ] || [ -L "$e" ] || continue; cp -a "$e" /opt/open-slide/template/; \
       done \
    && cp -a /opt/open-slide/src/packages/core/skills /opt/open-slide/template/.agents/skills \
    && test -f /opt/open-slide/template/.claude/skills/create-slide/SKILL.md \
    && printf 'node_modules\ndist\n.DS_Store\n' > /opt/open-slide/template/.gitignore \
    && rm -rf /opt/open-slide/src

# Label the seeded starter deck so it cannot pass for the user's own deck
# (#3560). Edits only the template copy; fails the build if the pinned upstream
# deck no longer has the shape the script anchors on.
COPY images/slides-agent/label-starter-deck.mjs /tmp/label-starter-deck.mjs
RUN node /tmp/label-starter-deck.mjs /opt/open-slide/template/slides/getting-started/index.tsx \
    && grep -q STARTER_DECK_LABEL /opt/open-slide/template/slides/getting-started/index.tsx \
    && rm -f /tmp/label-starter-deck.mjs

WORKDIR /opt/open-slide/app
RUN rm -rf slides themes netlify.toml vercel.json README.md
COPY images/slides-agent/open-slide.config.ts ./open-slide.config.ts
# The container runs as the box user (arbitrary uid). The dev server writes
# current.json under its cwd's node_modules/.open-slide, Vite bundles
# open-slide.config.ts into a temporary .mjs beside it, and Vite's dependency
# pre-bundle cache sits under the core package's own node_modules (its app
# directory is Vite's root). Those directories are world-writable with the
# sticky bit; the files in them (package.json, the config, the installed
# packages) stay root-owned.
RUN mkdir -p node_modules/.open-slide node_modules/@open-slide/core/node_modules/.vite \
    && chmod 1777 . node_modules/.open-slide node_modules/@open-slide/core/node_modules/.vite

# --- runtime ----------------------------------------------------------------
FROM ${NODE_IMAGE}
# apt-get upgrade: security patches that shipped since the base's last rebuild
# (same reasoning as images/agent-box/Dockerfile). chromium: Debian's package,
# for headless PDF/PNG rendering; fonts so text renders the same everywhere.
RUN apt-get update \
    && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends \
         ca-certificates curl \
         chromium fonts-liberation fonts-noto-core fonts-noto-color-emoji \
    && rm -rf /var/lib/apt/lists/* \
    # The runtime needs node only. The base image's bundled npm, npx, corepack
    # and yarn are package managers with their own dependency trees (and the
    # fixed HIGH findings that come with them); nothing in the image runs them.
    && rm -rf /usr/local/lib/node_modules /usr/local/bin/np[mx] \
         /usr/local/bin/corepack /usr/local/bin/yarn /usr/local/bin/yarnpkg /opt/yarn-v* \
    && test ! -e /usr/local/bin/npm \
    && node --version

COPY --from=caddy /out/caddy /usr/bin/caddy
COPY --from=wsauth /out/slides-wsauth /usr/local/bin/slides-wsauth
COPY --from=build /opt/open-slide /opt/open-slide
COPY images/slides-agent/Caddyfile /etc/caddy/Caddyfile
# Plain COPY + chmod (not COPY --chmod) so the image also builds with the
# legacy builder, not only BuildKit.
COPY images/slides-agent/entrypoint.sh /usr/local/bin/slides-agent-entrypoint
COPY images/slides-agent/slides-render /usr/local/bin/slides-render
COPY images/slides-agent/open-slide /usr/local/bin/open-slide
COPY images/slides-agent/slides-print-pdf /usr/local/bin/slides-print-pdf
RUN chmod 0755 /usr/local/bin/slides-agent-entrypoint /usr/local/bin/slides-render /usr/local/bin/open-slide /usr/local/bin/slides-print-pdf \
    && node --check /usr/local/bin/slides-print-pdf \
    && chmod 0644 /etc/caddy/Caddyfile \
    # The proxy config must parse with the placeholders filled: a Caddyfile
    # that fails here would otherwise fail on every box start.
    && SLIDES_AUTH_USER=build-check \
       SLIDES_AUTH_HASH="$(caddy hash-password --plaintext build-check)" \
       caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile \
    && chromium --version

ENV HOME=/tmp/slides-home \
    CHROME_BIN=/usr/bin/chromium
# The auth proxy; the dev server stays on 127.0.0.1:5173. Documentation only:
# the recipe runs the container on the box's host network.
EXPOSE 8080
# Default uid; the recipe overrides it with the box user's uid:gid.
USER 1000
ENTRYPOINT ["/usr/local/bin/slides-agent-entrypoint"]
