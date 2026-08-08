# Talks

Slides live in **[FootprintAI/talks](https://github.com/FootprintAI/talks)**, the
collection that holds every public talk we give. This page is the stable
pointer — link to it from a slide, a QR code or a conference programme, and it
keeps working after a deck is revised or renamed.

## Containarium

| When | Where | Deck |
| --- | --- | --- |
| 2026-08 | COSCUP, Taipei | [Containarium — an SSH-native agent runtime](https://github.com/FootprintAI/talks/blob/main/slides/202608-containarium-coscup2026.pdf) |

*An SSH-native agent runtime, built because our hardware was sitting idle* —
where utilisation goes on AI and VM fleets, why one VM per developer stopped
paying for itself, and how LXC + sshpiper + persistent disk became
Containarium.

## Why the slides are not in this repo

One canonical copy, in the repo whose job is talks. A deck that lives in two
places is a deck where one copy is quietly out of date — which is exactly what
happened here: this directory held an export that was already a revision
behind the one in the talks repo.

Decks are also large binaries that change often and have nothing to do with
building or running Containarium. Keeping them out means cloning this
repository does not drag along every slide we have ever presented.

## Adding a talk

Put the PDF in [FootprintAI/talks](https://github.com/FootprintAI/talks) under
`slides/`, following the `YYYYMM-title.pdf` convention already in use there,
then add a row to the table above and an entry under **In the wild** in the
[root README](../../README.md).
