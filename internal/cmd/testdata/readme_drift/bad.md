# Drift fixture — every invocation below is deliberately wrong

Read by TestREADMEDriftChecker_CatchesBadFixture. Each line is one drift the
checker must report; if it stops reporting any of them, the README drift
test can no longer fail and is worthless.

## Commands

```bash
# A real verb with a flag that does not exist.
containarium create alice --no-such-flag

# A verb that does not exist.
containarium frobnicate alice

# A real group with a subcommand that does not exist.
containarium ssh-config synchronise

# A bad flag hidden behind sudo, an env prefix and a line continuation.
sudo CONTAINARIUM_HTTP=true containarium list \
  --definitely-not-a-flag
```

Links: [a heading that exists](#commands) and
[one that does not](#no-such-section).
