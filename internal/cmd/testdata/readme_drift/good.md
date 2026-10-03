# Drift fixture — every invocation below is valid

Read by TestREADMEDriftChecker_AcceptsGoodFixture, so the checker is proven
not to flag the shell shapes the README actually uses.

## Shapes the checker must accept

```bash
# continuation lines, inherited persistent flags, flag=value
containarium create alice \
  --ssh-key ~/.ssh/id_ed25519.pub \
  --server=http://localhost:8080 --http
export CONTAINARIUM_TOKEN="$(sudo cat /etc/containarium/admin.token)"
sudo containarium list -v   # trailing comment: --not-a-flag
containarium ssh-config sync --sentinel sentinel.example.com && ssh alice
containarium code install alice --help
containariumd daemon --this-is-not-checked
echo "containarium is mentioned in a string --ignored"
```

```jsonc
{ "command": "containarium", "args": ["create", "--not-checked"] }
```

See [the shapes](#shapes-the-checker-must-accept).
