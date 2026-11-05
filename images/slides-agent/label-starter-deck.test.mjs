// node --test images/slides-agent/label-starter-deck.test.mjs  (#3560)
import test from 'node:test';
import assert from 'node:assert/strict';
import { label, MARKER, TITLE, BANNER } from './label-starter-deck.mjs';

const DECK = [
  "export const meta: SlideMeta = {",
  "  title: 'Getting started',",
  "};",
  "A.transition = fade;",
  "export default [",
  "  A,",
  "  B,",
  "] satisfies Page[];",
  "",
].join('\n');

test('retitles the deck, wraps every page, and keeps the default export', () => {
  const out = label(DECK);
  assert.ok(out.includes(`title: '${TITLE}',`));
  assert.ok(!out.includes("title: 'Getting started'"));
  assert.ok(out.includes('const starterPages = ['));
  assert.ok(out.includes('export default starterPages.map(withStarterBanner) satisfies Page[];'));
  assert.equal(out.split('export default').length - 1, 1, 'exactly one default export');
  assert.ok(out.includes(BANNER));
  assert.ok(out.includes(MARKER));
});

test('the wrapper keeps a page transition', () => {
  assert.ok(label(DECK).includes('if (P.transition) Labelled.transition = P.transition;'));
});

test('the wrapper is placed after the page array, so assignments to pages run first', () => {
  const out = label(DECK);
  assert.ok(out.indexOf('A.transition = fade;') < out.indexOf('withStarterBanner = '));
  assert.ok(out.indexOf('] satisfies Page[];') < out.indexOf('withStarterBanner = '));
});

test('fails, not skips, when an anchor is missing', () => {
  for (const [anchor, repl] of [
    ["title: 'Getting started',", "title: 'Intro',"],
    ['export default [', 'export const pages = ['],
    ['] satisfies Page[];', '];'],
  ]) {
    assert.throws(() => label(DECK.replace(anchor, repl)), /expected exactly one/);
  }
});

test('fails when an anchor appears more than once', () => {
  assert.throws(() => label(DECK + "\n  title: 'Getting started',\n"), /found 2/);
});

test('refuses to label a deck twice', () => {
  assert.throws(() => label(label(DECK)), /already labelled/);
});

test('fails when the array anchors are out of order', () => {
  const swapped = [
    "title: 'Getting started',",
    '] satisfies Page[];',
    'export default [',
  ].join('\n');
  assert.throws(() => label(swapped), /out of order/);
});
