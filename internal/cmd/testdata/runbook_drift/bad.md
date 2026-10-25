# Bad runbook (fixture: every mistake below is planted)

## Section

```bash
containarium backends upgrade --no-such-flag
containariumd recover --dry-run
containariumd frobnicate
```

Inline: run `containarium snapshot rollback alice snap --not-a-flag` first.

See [missing file](does-not-exist.md).

See [bad cross anchor](good-target.md#no-such-heading).

See [good cross anchor](good-target.md#real-heading) and [in page](#section).

See [bad in-page](#nope).
