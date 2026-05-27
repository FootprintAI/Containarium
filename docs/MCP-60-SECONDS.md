# 60 Seconds: Create + Expose a Container from MCP

The fastest path from `containarium login` to an HTTPS URL serving a
container. Targets the Containarium Cloud surface; works for self-hosted
deployments if you swap the URL.

K5 of the Free-vs-Paid-Tier-Gates work (cloud#147). Companion to the
broader [MCP-QUICKSTART.md](MCP-QUICKSTART.md) — that one walks the full
Claude Desktop setup; this one is the agent-friendly path once the MCP
server is already wired.

---

## What you need

- `containarium` CLI installed (see `hacks/install-cli.sh`).
- A Containarium Cloud account. Sign up at the cloud's login page — a
  personal-sandbox org + a `default` API token are auto-provisioned for
  you. If you've already signed up via the dashboard, you're set.
- An MCP-capable client (Claude Desktop, Cursor, etc.) wired to the
  cloud's MCP server endpoint.

## Step 1 — Log in (10s)

```bash
containarium login
```

Opens a browser tab for one-click approval. On success you'll see:

```
✓ Logged in as you@example.com
✓ API token saved to /home/you/.containarium/credentials.json
  → View / rotate at https://<your-host>/settings/api-tokens
```

The saved token is the same one MCP clients use — they read
`credentials.json` directly via the
[MCP credentials fallback](../internal/mcp/credentials_fallback_test.go).

## Step 2 — Tell your agent (5s)

In your MCP client (e.g. Claude Desktop), ask:

> Create a container named `demo`, run `python3 -m http.server 8080` in
> it, and expose port 8080 publicly.

## Step 3 — Watch the agent run two tools (~45s)

Under the hood your agent calls:

1. **`create_container`** — provisions an LXC container under your org.
2. *(agent SSHes in and starts the HTTP server — uses the MCP `ssh`
   bridge or a separate shell session.)*
3. **`expose_port`** — claims a subdomain and wires it through the
   cloud's HTTPS proxy.

A successful `expose_port` response includes the public URL, e.g.
`https://demo-<hash>.<your-host>`. Open it in a browser — your container
is serving traffic.

## Tier-specific URL shape

- **Free** (`is_personal=true` org): URL is `<name>-<8-char-hash>.<host>`.
  The hash is deterministic per (name, org_id) — re-claiming after a
  delete produces the same URL (no cert churn, bookmarks survive).
- **Pro / Enterprise**: clean `<name>.<host>`. Subject to the per-tier
  subdomain quota (Pro = 25 soft-capped; Enterprise unlimited).

If you're on Free and want a clean URL, upgrade in the dashboard. The
existing kept-alive URLs stay live during the upgrade.

## What happens if the agent's request fails

- **`401 unauthorized`**: token isn't in `credentials.json`. Re-run
  `containarium login`.
- **`403 / failed_precondition: personal-tier-org-no-invite`**: not
  related to container ops — that's the team-invite gate. Container +
  expose work on every tier.
- **Container created but expose_port fails with `quota_exceeded`**:
  you're at the subdomain limit. Delete an unused subdomain via the
  dashboard or upgrade.

## Related docs

- [MCP-QUICKSTART.md](MCP-QUICKSTART.md) — full Claude Desktop +
  Containarium-host setup (where this 60-second flow assumes you've
  already landed).
- [MCP-INTEGRATION.md](MCP-INTEGRATION.md) — protocol-level notes for
  building your own MCP-capable client.
- `prd/cloud/free-vs-paid-tier-gates.md` (cloud repo, private) — the
  PRD this 60-second flow is the user-facing surface of.
