'use client';

import { useState, useEffect, useCallback } from 'react';
import { RefreshCw, Loader2, CheckCircle2, AlertTriangle, ArrowUpCircle } from 'lucide-react';
import { Server } from '@/src/types/server';
import { BackendInfo } from '@/src/types/container';
import { getClient } from '@/src/lib/api/client';

interface VersionsViewProps { server: Server; }

interface LatestRelease { latestRelease: string; currentVersion: string; updateAvailable: boolean; }

// normalizeVersion strips a leading "v" so "v0.22.0" and "0.22.0" compare equal.
function normalizeVersion(v: string): string {
  return (v || '').replace(/^v/, '').trim();
}

export default function VersionsView({ server }: VersionsViewProps) {
  const [backends, setBackends] = useState<BackendInfo[]>([]);
  const [latest, setLatest] = useState<LatestRelease | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string>('');
  const [upgrading, setUpgrading] = useState<Record<string, boolean>>({});
  const [notice, setNotice] = useState<string>('');

  const load = useCallback(async () => {
    try {
      const client = getClient(server);
      const [bs, lr] = await Promise.all([
        client.listBackends(),
        client.getLatestRelease().catch(() => null),
      ]);
      setBackends(bs);
      setLatest(lr);
      setError('');
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to load versions');
    } finally {
      setLoading(false);
    }
  }, [server]);

  useEffect(() => {
    setLoading(true);
    load();
  }, [load]);

  const latestTag = latest?.latestRelease || '';

  // Trigger an upgrade, then poll list_backends until this backend's version
  // changes and it's healthy again (the daemon restarts mid-upgrade). #354.
  const handleUpgrade = useCallback(async (backendId: string, fromVersion: string) => {
    const key = backendId || '(local)';
    setUpgrading((u) => ({ ...u, [key]: true }));
    setNotice('');
    try {
      const client = getClient(server);
      const res = await client.triggerBackendUpgrade(backendId, false);
      setNotice(
        `Upgrade ${res.status} on ${key} (job ${res.upgradeId}). ` +
        `The daemon restarts if a new binary is applied — this view refreshes as the version changes.`,
      );

      const startedAt = Date.now();
      const poll = setInterval(async () => {
        try {
          const bs = await getClient(server).listBackends();
          setBackends(bs);
          const b = bs.find((x) => x.id === backendId) ||
            (backendId === '' ? bs.find((x) => x.type === 'local') : undefined);
          const changed = b && b.healthy &&
            normalizeVersion(b.version || '') !== normalizeVersion(fromVersion);
          if (changed || Date.now() - startedAt > 5 * 60 * 1000) {
            clearInterval(poll);
            setUpgrading((u) => ({ ...u, [key]: false }));
            load();
          }
        } catch {
          /* ignore transient poll errors — the daemon may be restarting */
        }
      }, 3000);
    } catch (e) {
      setNotice(e instanceof Error ? e.message : 'Upgrade failed');
      setUpgrading((u) => ({ ...u, [key]: false }));
    }
  }, [server, load]);

  if (loading) {
    return (
      <div className="flex items-center gap-2 p-6 text-[var(--text-muted)]">
        <Loader2 className="h-4 w-4 animate-spin" /> Loading versions…
      </div>
    );
  }

  return (
    <div className="p-4">
      <div className="mb-4 flex items-center justify-between">
        <div>
          <h2 className="text-lg font-semibold">Versions</h2>
          <p className="text-xs text-[var(--text-muted)]">
            Daemon version per backend vs the latest GitHub release
            {latestTag ? <> — latest: <span className="font-medium">{latestTag}</span></> : <> — latest: unknown</>}
          </p>
        </div>
        <button
          onClick={() => { setLoading(true); load(); }}
          className="flex items-center gap-1.5 rounded-lg border border-[var(--border-subtle)] bg-[var(--surface)] px-3 py-1.5 text-sm hover:bg-[var(--surface-2)]"
        >
          <RefreshCw className="h-3.5 w-3.5" /> Refresh
        </button>
      </div>

      {error && (
        <div className="mb-3 rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-[var(--c-red)]">{error}</div>
      )}
      {notice && (
        <div className="mb-3 rounded-lg border border-blue-500/30 bg-blue-500/10 px-3 py-2 text-sm text-[var(--c-blue)]">{notice}</div>
      )}

      <div className="overflow-hidden rounded-xl border border-[var(--border-subtle)]">
        <table className="w-full text-sm">
          <thead className="bg-[var(--surface-2)] text-left text-xs text-[var(--text-muted)]">
            <tr>
              <th className="px-4 py-2 font-medium">Backend</th>
              <th className="px-4 py-2 font-medium">Type</th>
              <th className="px-4 py-2 font-medium">Current</th>
              <th className="px-4 py-2 font-medium">Latest</th>
              <th className="px-4 py-2 font-medium">Status</th>
              <th className="px-4 py-2 text-right font-medium">Action</th>
            </tr>
          </thead>
          <tbody>
            {backends.map((b) => {
              const current = b.version || '';
              const behind = !!latestTag && normalizeVersion(current) !== normalizeVersion(latestTag);
              const key = b.id || '(local)';
              const busy = !!upgrading[key];
              return (
                <tr key={b.id} className="border-t border-[var(--border-subtle)]">
                  <td className="px-4 py-2 font-medium">
                    {b.id}
                    {b.hostname ? <span className="text-[var(--text-muted)]"> · {b.hostname}</span> : null}
                  </td>
                  <td className="px-4 py-2 text-[var(--text-muted)]">{b.type}</td>
                  <td className="px-4 py-2 font-mono">{current || '—'}</td>
                  <td className="px-4 py-2 font-mono">{latestTag || '—'}</td>
                  <td className="px-4 py-2">
                    {!b.healthy ? (
                      <span className="inline-flex items-center gap-1 text-[var(--text-muted)]"><AlertTriangle className="h-3.5 w-3.5" /> offline</span>
                    ) : behind ? (
                      <span className="inline-flex items-center gap-1 text-[var(--c-amber)]"><AlertTriangle className="h-3.5 w-3.5" /> behind</span>
                    ) : (
                      <span className="inline-flex items-center gap-1 text-[var(--c-emerald)]"><CheckCircle2 className="h-3.5 w-3.5" /> current</span>
                    )}
                  </td>
                  <td className="px-4 py-2 text-right">
                    <button
                      onClick={() => handleUpgrade(b.id, current)}
                      disabled={busy || !b.healthy}
                      className="inline-flex items-center gap-1.5 rounded-lg border border-[var(--border-subtle)] bg-[var(--surface)] px-3 py-1.5 text-xs hover:bg-[var(--surface-2)] disabled:cursor-not-allowed disabled:opacity-50"
                      title="Pull the sentinel-served binary, verify, and restart this daemon"
                    >
                      {busy ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <ArrowUpCircle className="h-3.5 w-3.5" />}
                      {busy ? 'Upgrading…' : 'Upgrade now'}
                    </button>
                  </td>
                </tr>
              );
            })}
            {backends.length === 0 && (
              <tr><td colSpan={6} className="px-4 py-6 text-center text-[var(--text-muted)]">No backends.</td></tr>
            )}
          </tbody>
        </table>
      </div>

      <p className="mt-3 text-xs text-[var(--text-muted)]">
        “Upgrade now” pulls the binary the sentinel currently serves (SHA-verified + smoke-tested), swaps it
        atomically, and restarts the daemon. The latest-GitHub column is for visibility; bringing the sentinel
        up to a new release is a separate operator step.
      </p>
    </div>
  );
}
