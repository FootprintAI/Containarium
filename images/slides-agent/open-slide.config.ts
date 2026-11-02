// open-slide configuration baked into the slides-agent image
// (images/slides-agent/Dockerfile). The dev server's cwd is the image's
// copy of upstream's demo app (package.json + node_modules); the deck tree it serves is the
// bind-mounted /workspace on the box disk, so decks survive container and box
// restarts.
import type { OpenSlideConfig } from '@open-slide/core';

// SLIDES_ALLOWED_HOSTS: comma-separated hostnames the dev server accepts.
// Empty means any host: requests only ever arrive through the in-box auth
// proxy, which is the access control; the host check is not.
const allowedHosts = (process.env.SLIDES_ALLOWED_HOSTS ?? '')
  .split(',')
  .map((h) => h.trim())
  .filter((h) => h.length > 0);

const openSlideConfig: OpenSlideConfig = {
  port: 5173,
  slidesDir: '/workspace/slides',
  themesDir: '/workspace/themes',
  assetsDir: '/workspace/assets',
  allowedHosts: allowedHosts.length > 0 ? allowedHosts : true,
  // The in-app agent panel runs commands in the workspace and is gated only
  // on a loopback peer. Behind the host-network proxy every request is a
  // loopback peer, so the gate is void: keep the route off. The coding agent
  // in this box is Claude Code on the box itself, driven over agent-box.
  agent: { enabled: false },
};

export default openSlideConfig;
