'use client';

import { useState, useMemo, useEffect, useCallback } from 'react';
import { Bot, ExternalLink, RefreshCw, Loader2, MessagesSquare, SlidersHorizontal } from 'lucide-react';
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
 * (https://<box>-workspace.<domain>/__ws_login?t=<token>) that sets the in-box
 * SameSite=None session cookie and redirects to the workspace UI, so no sign-in
 * prompt is shown.
 *
 * Model provider + key: rather than reimplement OpenHands' (internal, fast-
 * moving, session-key-gated) settings API in our chrome, the "Model setup"
 * view deep-links the iframe to OpenHands' own Settings → LLM page
 * (/settings/llm), which already supports Anthropic, OpenAI/Codex, Gemini,
 * Mistral, and any LiteLLM provider, plus saved profiles. The bootstrap cookie
 * set by the chat view authenticates that page too.
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

  const [bootstrapSrc, setBootstrapSrc] = useState<string>('');
  const [loading, setLoading] = useState(false);
  const [needsSignin, setNeedsSignin] = useState(false);
  const [tab, setTab] = useState<'chat' | 'settings'>('chat');
  const [reloadKey, setReloadKey] = useState(0);

  const loadAccess = useCallback(async () => {
    if (!activeDomain) return;
    const fallback = `https://${activeDomain}`;
    setLoading(true);
    setNeedsSignin(false);
    try {
      const access = activeName ? await getClient(server).getWorkspaceAccess(activeName) : null;
      if (access?.url) {
        setBootstrapSrc(access.url);
      } else {
        setBootstrapSrc(fallback);
        setNeedsSignin(true);
      }
    } catch {
      setBootstrapSrc(fallback);
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

  // Chat view loads the bootstrap URL (sets the cookie, lands on the app).
  // Model setup deep-links to OpenHands' own LLM settings; the cookie set by the
  // chat view's bootstrap load authenticates it.
  const iframeSrc = tab === 'settings' ? `https://${activeDomain}/settings/llm` : bootstrapSrc;

  const tabBtn = (id: 'chat' | 'settings', label: string, Icon: typeof MessagesSquare) => (
    <button
      onClick={() => setTab(id)}
      className={[
        'flex items-center gap-1.5 rounded-lg px-2.5 py-1.5 text-xs transition-colors',
        tab === id
          ? 'bg-[var(--surface-2)] text-[var(--text)]'
          : 'text-[var(--text-secondary)] hover:bg-[var(--surface-2)]',
      ].join(' ')}
    >
      <Icon size={13} /> {label}
    </button>
  );

  return (
    <div className="flex h-[calc(100vh-150px)] flex-col">
      <div className="flex items-center gap-2 border-b border-[var(--border-subtle)] bg-[var(--surface)] px-4 py-2 shrink-0">
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
        <div className="ml-2 flex items-center gap-1">
          {tabBtn('chat', 'Chat', MessagesSquare)}
          {tabBtn('settings', 'Model setup', SlidersHorizontal)}
        </div>
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
            href={iframeSrc || `https://${activeDomain}`}
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center gap-1.5 rounded-lg border border-[var(--border-subtle)] bg-[var(--surface)] px-2.5 py-1.5 text-xs text-[var(--text-secondary)] hover:bg-[var(--surface-2)]"
          >
            <ExternalLink size={13} /> Open in new tab
          </a>
        </div>
      </div>
      {tab === 'settings' && (
        <div className="border-b border-[var(--border-subtle)] bg-[var(--surface)] px-4 py-1.5 text-xs text-[var(--text-muted)]">
          Pick your provider and paste an API key — Anthropic, OpenAI / Codex, Google Gemini, Mistral, or any LiteLLM model. Saved per box; you can keep multiple profiles.
        </div>
      )}
      <div className="relative flex-1">
        {loading || !iframeSrc ? (
          <div className="flex h-full items-center justify-center">
            <Loader2 size={22} className="animate-spin text-[var(--text-secondary)]" />
          </div>
        ) : (
          <iframe
            key={`${tab}-${activeDomain}-${reloadKey}`}
            src={iframeSrc}
            className="absolute inset-0 h-full w-full border-0"
            title={`Agent workspace — ${activeDomain}`}
          />
        )}
      </div>
    </div>
  );
}
