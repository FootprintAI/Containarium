#!/usr/bin/env node
// Label the seeded starter deck (#3560). Run at image build time against the
// template copy of upstream open-slide's scaffold deck, before it is seeded
// into /workspace:
//   node label-starter-deck.mjs <path/to/slides/getting-started/index.tsx>
//
// The deck is upstream's, pinned by commit in the Dockerfile. This script edits
// a copy of it with three exact-text anchors, each of which must match exactly
// once. If a pin bump changes the file so an anchor no longer matches, the
// script exits non-zero and the image build fails; it never silently leaves the
// deck unlabelled.
//
// What it does:
//   1. the deck title becomes TITLE, so any list or title bar says it is a starter;
//   2. every page is wrapped to render a BANNER across the top of the page.
//      The wrapper keeps a page's `transition` and renders the page as a child,
//      so hooks and per-page behaviour are unchanged.
//
// The label exists only in the seeded copy. A user's deck, or an agent that
// rewrites this file, replaces it, and the label goes with it.

import { readFileSync, writeFileSync } from 'node:fs';

export const MARKER = 'STARTER_DECK_LABEL';
export const TITLE = 'Starter deck (example, not your deck)';
export const BANNER = 'STARTER DECK: an example, not your deck';

const ANCHOR_TITLE = "title: 'Getting started',";
const ANCHOR_DEFAULT_OPEN = 'export default [';
const ANCHOR_DEFAULT_CLOSE = '] satisfies Page[];';

const WRAPPER = `
// ${MARKER}: added at image build (images/slides-agent/label-starter-deck.mjs).
const withStarterBanner = (P: Page): Page => {
  const Labelled: Page = () => (
    <>
      <P />
      <div
        role="note"
        style={{
          position: 'absolute',
          left: 0,
          right: 0,
          top: 0,
          zIndex: 2147483647,
          padding: '12px 24px',
          background: '#de3b3d',
          color: '#ffffff',
          fontSize: 28,
          fontWeight: 600,
          textAlign: 'center',
          pointerEvents: 'none',
        }}
      >
        ${BANNER}
      </div>
    </>
  );
  if (P.transition) Labelled.transition = P.transition;
  return Labelled;
};

export default starterPages.map(withStarterBanner) satisfies Page[];
`;

function once(src, anchor, what) {
  const n = src.split(anchor).length - 1;
  if (n !== 1) {
    throw new Error(`label-starter-deck: expected exactly one ${what} (${JSON.stringify(anchor)}), found ${n}`);
  }
}

export function label(src) {
  if (src.includes(MARKER)) throw new Error('label-starter-deck: deck is already labelled');
  once(src, ANCHOR_TITLE, 'deck title');
  once(src, ANCHOR_DEFAULT_OPEN, 'default page array');
  once(src, ANCHOR_DEFAULT_CLOSE, 'end of page array');
  if (src.indexOf(ANCHOR_DEFAULT_OPEN) > src.indexOf(ANCHOR_DEFAULT_CLOSE)) {
    throw new Error('label-starter-deck: page array anchors are out of order');
  }
  return src
    .replace(ANCHOR_TITLE, `title: ${JSON.stringify(TITLE).replace(/^"|"$/g, "'")},`)
    .replace(ANCHOR_DEFAULT_OPEN, 'const starterPages = [')
    .replace(ANCHOR_DEFAULT_CLOSE, ANCHOR_DEFAULT_CLOSE + '\n' + WRAPPER);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const file = process.argv[2];
  if (!file) {
    console.error('usage: label-starter-deck.mjs <index.tsx>');
    process.exit(2);
  }
  writeFileSync(file, label(readFileSync(file, 'utf8')));
  console.log(`label-starter-deck: labelled ${file}`);
}
