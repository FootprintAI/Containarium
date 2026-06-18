'use client';

import { useState, useMemo, useEffect, useCallback } from 'react';
import { Bot, ExternalLink, RefreshCw, Loader2 } from 'lucide-react';
import { ProxyRoute } from '@/src/types/app';
import { Server } from '@/src/types/server';
import { getClient } from '@/src/lib/api/client';

/**
 * WorkspaceView embeds an agent-workspace box's web chat UI (OpenHands,
 * deployed via the `agent-workspace` recipe) in an iframe, so users can
 * co-work with a coding agent without leaving the console.
 *
 * The box exposes its in-box auth proxy on the `workspace` subdomain (recipe
 * container port 8080); we discover those routes from the network route list.
 *
 * Zero-click auth: the daemon's GetWorkspaceAccess returns a bootstrap URL
 * (https://<box>-workspace.<domain>/__ws_login?t=<token>). Loading it in the
 * iframe sets the in-box SameSite=None session cookie and redirects to the
 * workspace UI, so no sign-in prompt is ever shown. If that lookup fails (older
 * box, no route), we fall back to the plain workspace URL and surface the
 * "Open in new tab to sign in" path.
 */
export default function WorkspaceView({ server, routes }: { server: Server; routes: ProxyRoute[] }) {
  const workspaces = useMemo(
    () =>
      (routes || []).filter(
        (r) => r.active && (r.subdomain?.includes('workspace') || r.port === 8080)
      ),
    [routes]
  );

  const [selected, setSelected] = useState<string>('');
  const active = workspaces.find((w) => w.fullDomain === selected) ?? workspaces[0];
  const activeDomain = active?.fullDomain;
  const activeName = active?.username;

  const [src, setSrc] = useState<string>('');
  const [loading, setLoading] = useState(false);
  const [needsSignin, setNeedsSignin] = useState(false);
  const [reloadKey, setReloadKey] = useState(0);

  const loadAccess = useCallback(async () => {
    if (!activeDomain) return;
    const fallback = `https://${activeDomain}`;
    setLoading(true);
    setNeedsSignin(false);
    try {
      // Prefer the zero-click bootstrap URL from the daemon.
      const access = activeName ? await getClient(server).getWorkspaceAccess(activeName) : null;
      if (access?.url) {
        setSrc(access.url);
      } else {
        setSrc(fallback);
        setNeedsSignin(true);
      }
    } catch {
      // Older box / no token endpoint — fall back to manual sign-in.
      setSrc(fallback);
      setNeedsSignin(true);
    } finally {
      setLoading(false);
    }
  }, [server, activeDomain, activeName]);

  useEffect(() => {
    loadAccess();
  }, [loadAccess]);

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

  return (
    <div className="flex h-[calc(100vh-150px)] flex-col">
      <div className="flex items-center gap-3 border-b border-[var(--border-subtle)] bg-[var(--surface)] px-4 py-2 shrink-0">
        <Bot size={14} className="text-[var(--accent)]" />
        {workspaces.length > 1 ? (
          <select
            value={active?.fullDomain ?? ''}
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
          <span className="text-xs font-medium text-[var(--text)]">{activeDomain}</span>
        )}
        {needsSignin && (
          <span className="text-xs text-[var(--c-amber)]">sign in once in a new tab →</span>
        )}
        <div className="ml-auto flex items-center gap-1.5">
          <button
            onClick={() => { setReloadKey((k) => k + 1); loadAccess(); }}
            title="Reload"
            className="rounded-lg border border-[var(--border-subtle)] bg-[var(--surface)] p-1.5 text-[var(--text-secondary)] hover:bg-[var(--surface-2)]"
          >
            <RefreshCw size={13} />
          </button>
          <a
            href={src || `https://${activeDomain}`}
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center gap-1.5 rounded-lg border border-[var(--border-subtle)] bg-[var(--surface)] px-2.5 py-1.5 text-xs text-[var(--text-secondary)] hover:bg-[var(--surface-2)]"
          >
            <ExternalLink size={13} /> Open in new tab
          </a>
        </div>
      </div>
      <div className="relative flex-1">
        {loading || !src ? (
          <div className="flex h-full items-center justify-center">
            <Loader2 size={22} className="animate-spin text-[var(--text-secondary)]" />
          </div>
        ) : (
          <iframe
            key={`${src}-${reloadKey}`}
            src={src}
            className="absolute inset-0 h-full w-full border-0"
            title={`Agent workspace — ${activeDomain}`}
          />
        )}
      </div>
    </div>
  );
}
