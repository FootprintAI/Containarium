# containarium-slides-agent
#
# The prebaked image the `slides-agent` recipe (pkg/core/recipes/recipes.yaml,
# #3434) runs inside a box via podman: Node, the open-slide slide framework
# (MIT) built from a pinned commit with its dependencies installed, a headless
# Chromium for PDF export, and the Caddy auth proxy that fronts the dev server.
# Everything a box needs at start is in here, so starting a box fetches
# nothing from a package registry; the image pull is the only fetch.
#
# Layout inside the image:
#   /opt/open-slide/workspace   package.json, node_modules, open-slide.config.ts
#                               (the dev server's cwd; not writable by the box user
#                               except the two cache dirs below)
#   /opt/open-slide/template    the scaffold's deck tree + agent files, seeded
#                               into the bind-mounted /workspace on first start
#   /workspace                  bind mount: the deck tree on the box disk
#   /etc/caddy/Caddyfile        the auth proxy (images/slides-agent/Caddyfile)
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
ARG CADDY_IMAGE=docker.io/library/caddy:2.11.7

# --- the proxy binary -------------------------------------------------------
FROM ${CADDY_IMAGE} AS caddy

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

WORKDIR /src
# Fetch exactly the pinned commit and verify the checkout is that commit.
RUN git init -q . \
    && git remote add origin "${OPEN_SLIDE_REPO}" \
    && git fetch -q --depth 1 origin "${OPEN_SLIDE_COMMIT}" \
    && git checkout -q --detach FETCH_HEAD \
    && test "$(git rev-parse HEAD)" = "${OPEN_SLIDE_COMMIT}"

# The core package only, from the monorepo's lockfile. --ignore-scripts: no
# dependency lifecycle scripts (pnpm 10 already blocks them by default).
RUN pnpm install --frozen-lockfile --ignore-scripts --filter @open-slide/core \
    && pnpm --filter @open-slide/core run build \
    && mkdir -p /out \
    && (cd packages/core && npm pack --ignore-scripts --pack-destination /out >/dev/null)

# The workspace the dev server runs in: the scaffold template with its core
# dependency pointed at the tarball built above. The template's own dependency
# ranges (react, react-dom) resolve at image build time; the image digest pins
# the result.
WORKDIR /opt/open-slide/workspace
RUN cp -a /src/packages/cli/template/. . \
    && rm -f netlify.toml vercel.json \
    && TGZ="$(ls /out/open-slide-core-*.tgz)" \
    && sed -i "s|\"@open-slide/core\": \"[^\"]*\"|\"@open-slide/core\": \"file:${TGZ}\"|" package.json \
    && grep -q "\"@open-slide/core\": \"file:/out/" package.json \
    && pnpm install --ignore-scripts \
    && test -f node_modules/@open-slide/core/bin.js
COPY images/slides-agent/open-slide.config.ts ./open-slide.config.ts

# Split the deck tree and agent files out into the seed template; the
# workspace keeps only what the dev server needs as its cwd. The template's
# .claude/skills are relative symlinks into .agents/skills, which upstream
# generates from the core package's skills directory.
RUN mkdir -p /opt/open-slide/template/.agents \
    && for e in slides themes assets AGENTS.md CLAUDE.md README.md .claude; do \
         [ -e "$e" ] || [ -L "$e" ] || continue; mv "$e" /opt/open-slide/template/; \
       done \
    && cp -a /src/packages/core/skills /opt/open-slide/template/.agents/skills \
    && test -f /opt/open-slide/template/.claude/skills/create-slide/SKILL.md \
    && printf 'node_modules\ndist\n.DS_Store\n' > /opt/open-slide/template/.gitignore \
    # The container runs as the box user (arbitrary uid). The dev server writes
    # current.json under node_modules/.open-slide, Vite bundles
    # open-slide.config.ts into a temporary .mjs beside it, and Vite's
    # dependency pre-bundle cache sits under the core package's own
    # node_modules (its app directory is Vite's root). Those directories are
    # world-writable with the sticky bit; the files in them (package.json, the
    # config, the installed packages) stay root-owned.
    && mkdir -p node_modules/.open-slide node_modules/@open-slide/core/node_modules/.vite \
    && chmod 1777 . node_modules/.open-slide node_modules/@open-slide/core/node_modules/.vite \
    && test -w node_modules/@open-slide/core/node_modules/.vite

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
    && rm -rf /var/lib/apt/lists/*

COPY --from=caddy /usr/bin/caddy /usr/bin/caddy
COPY --from=build /opt/open-slide /opt/open-slide
COPY images/slides-agent/Caddyfile /etc/caddy/Caddyfile
# Plain COPY + chmod (not COPY --chmod) so the image also builds with the
# legacy builder, not only BuildKit.
COPY images/slides-agent/entrypoint.sh /usr/local/bin/slides-agent-entrypoint
COPY images/slides-agent/slides-render /usr/local/bin/slides-render
COPY images/slides-agent/open-slide /usr/local/bin/open-slide
RUN chmod 0755 /usr/local/bin/slides-agent-entrypoint /usr/local/bin/slides-render /usr/local/bin/open-slide \
    && chmod 0644 /etc/caddy/Caddyfile \
    # The proxy config must parse with the placeholders filled: a Caddyfile
    # that fails here would otherwise fail on every box start.
    && SLIDES_AUTH_USER=build-check \
       SLIDES_AUTH_HASH="$(caddy hash-password --plaintext build-check)" \
       SLIDES_WS_TOKEN=0123456789abcdef0123456789abcdef \
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
