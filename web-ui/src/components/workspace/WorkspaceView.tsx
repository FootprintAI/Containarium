'use client';

import { useState, useMemo } from 'react';
import { Bot, ExternalLink, RefreshCw } from 'lucide-react';
import { ProxyRoute } from '@/src/types/app';

/**
 * WorkspaceView embeds an agent-workspace box's web chat UI (OpenHands,
 * deployed via the `agent-workspace` recipe) in an iframe, so users can
 * co-work with a coding agent without leaving the console.
 *
 * The box exposes its in-box auth proxy on the `workspace` subdomain (recipe
 * container port 8080). We discover those routes from the network route list
 * rather than calling a new endpoint.
 *
 * Auth nuance: the workspace is protected by an in-box auth proxy, and
 * browsers suppress the basic-auth prompt inside a cross-origin iframe. So the
 * flow is: sign in ONCE in a new tab — the in-box proxy then issues a
 * SameSite=None session cookie, which the browser sends to the box even from
 * this embedded iframe, so every load afterward is seamless (no prompt). The
 * "Open in new tab to sign in" action is the one-time bootstrap; "Reload"
 * re-renders the iframe once the cookie is set.
 */
export default function WorkspaceView({ routes }: { routes: ProxyRoute[] }) {
  const workspaces = useMemo(
    () =>
      (routes || []).filter(
        (r) => r.active && (r.subdomain?.includes('workspace') || r.port === 8080)
      ),
    [routes]
  );

  const [selected, setSelected] = useState<string>('');
  const active = workspaces.find((w) => w.fullDomain === selected) ?? workspaces[0];
  const [reloadKey, setReloadKey] = useState(0);

  if (workspaces.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center gap-3 py-24">
        <Bot size={28} className="text-[var(--text-muted)]" />
        <p className="text-sm font-medium text-[var(--text-secondary)]">No agent workspace found</p>
        <p className="max-w-md text-center text-xs text-[var(--text-muted)]">
          Deploy one, then expose its UI on the <code className="rounded bg-[var(--surface-2)] px-1">workspace</code> subdomain:
        </p>
        <code className="rounded bg-[var(--surface-2)] px-2 py-1 text-xs text-[var(--text-secondary)]">
          containarium recipe deploy agent-workspace ws1 --param auth_password=…
        </code>
      </div>
    );
  }

  const src = `https://${active.fullDomain}`;

  return (
    <div className="flex h-[calc(100vh-150px)] flex-col">
      <div className="flex items-center gap-3 border-b border-[var(--border-subtle)] bg-[var(--surface)] px-4 py-2 shrink-0">
        <Bot size={14} className="text-[var(--accent)]" />
        {workspaces.length > 1 ? (
          <select
            value={active.fullDomain}
            onChange={(e) => setSelected(e.target.value)}
            className="rounded-lg border border-[var(--border-subtle)] bg-[var(--surface-2)] px-2 py-1 text-xs text-[var(--text)]"
          >
            {workspaces.map((w) => (
              <option key={w.fullDomain} value={w.fullDomain}>
                {w.username ? `${w.username} — ` : ''}{w.fullDomain}
              </option>
            ))}
          </select>
        ) : (
          <span className="text-xs font-medium text-[var(--text)]">{active.fullDomain}</span>
        )}
        <div className="ml-auto flex items-center gap-1.5">
          <button
            onClick={() => setReloadKey((k) => k + 1)}
            title="Reload"
            className="rounded-lg border border-[var(--border-subtle)] bg-[var(--surface)] p-1.5 text-[var(--text-secondary)] hover:bg-[var(--surface-2)]"
          >
            <RefreshCw size={13} />
          </button>
          <a
            href={src}
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center gap-1.5 rounded-lg border border-[var(--border-subtle)] bg-[var(--surface)] px-2.5 py-1.5 text-xs text-[var(--text-secondary)] hover:bg-[var(--surface-2)]"
          >
            <ExternalLink size={13} /> Open in new tab to sign in
          </a>
        </div>
      </div>
      <div className="relative flex-1">
        <iframe
          key={reloadKey}
          src={src}
          className="absolute inset-0 h-full w-full border-0"
          title={`Agent workspace — ${active.fullDomain}`}
        />
      </div>
    </div>
  );
}
