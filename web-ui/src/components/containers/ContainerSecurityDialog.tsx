'use client';

import { useState, useEffect, useCallback } from 'react';
import { X, RefreshCw, Loader2, CheckCircle2 } from 'lucide-react';
import { Server } from '@/src/types/server';
import { PentestFinding, PentestScanRun } from '@/src/types/security';
import { getClient } from '@/src/lib/api/client';

interface Props {
  open: boolean;
  onClose: () => void;
  containerName: string;
  username: string;
  server: Server;
}

type FixState = { status: 'idle' } | { status: 'loading' } | { status: 'done'; oldVersion: string; newVersion: string; packageName: string } | { status: 'error'; message: string };

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info'];

function severityColor(s: string) {
  if (s === 'critical' || s === 'high') return 'text-red-400';
  if (s === 'medium') return 'text-amber-400';
  return 'text-zinc-400';
}

function severityBg(s: string) {
  if (s === 'critical' || s === 'high') return 'border-red-500/20 bg-red-500/5';
  if (s === 'medium') return 'border-amber-500/20 bg-amber-500/5';
  return 'border-zinc-700 bg-zinc-800/40';
}

function relativeTime(iso: string): string {
  if (!iso) return 'never';
  const diff = Date.now() - new Date(iso).getTime();
  const m = Math.floor(diff / 60000);
  if (m < 2) return 'just now';
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
}

export default function ContainerSecurityDialog({ open, onClose, containerName, username, server }: Props) {
  const [findings, setFindings] = useState<PentestFinding[]>([]);
  const [lastRun, setLastRun] = useState<PentestScanRun | null>(null);
  const [loadingFindings, setLoadingFindings] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [fixStates, setFixStates] = useState<Record<number, FixState>>({});
  const [fixingAll, setFixingAll] = useState(false);

  const client = getClient(server);

  const fetchFindings = useCallback(async () => {
    setLoadingFindings(true);
    try {
      const [fr, sr] = await Promise.all([
        client.listPentestFindings({ containerName, status: 'open', limit: 200 }),
        client.listPentestScanRuns(containerName, 1, 0),
      ]);
      setFindings(fr.findings || []);
      setLastRun(sr.scanRuns?.[0] || null);
    } catch {
      // silent — show empty state
    } finally {
      setLoadingFindings(false);
    }
  }, [containerName, server]);

  useEffect(() => {
    if (open) {
      setFindings([]);
      setLastRun(null);
      setFixStates({});
      fetchFindings();
    }
  }, [open, fetchFindings]);

  const handleScan = async () => {
    setScanning(true);
    try {
      await client.triggerPentestScan(containerName);
      const poll = setInterval(async () => {
        try {
          const sr = await client.listPentestScanRuns(containerName, 1, 0);
          const run = sr.scanRuns?.[0];
          if (run && run.status !== 'running') {
            clearInterval(poll);
            setScanning(false);
            fetchFindings();
          }
        } catch {
          clearInterval(poll);
          setScanning(false);
        }
      }, 3000);
    } catch {
      setScanning(false);
    }
  };

  const handleFix = async (finding: PentestFinding) => {
    setFixStates(s => ({ ...s, [finding.id]: { status: 'loading' } }));
    try {
      const r = await client.remediatePentestFinding(finding.id);
      if (r.success) {
        setFixStates(s => ({ ...s, [finding.id]: { status: 'done', packageName: r.packageName, oldVersion: r.oldVersion, newVersion: r.newVersion } }));
      } else {
        setFixStates(s => ({ ...s, [finding.id]: { status: 'error', message: r.message } }));
      }
    } catch (e: any) {
      setFixStates(s => ({ ...s, [finding.id]: { status: 'error', message: e?.message || 'Failed' } }));
    }
  };

  const fixableHighCrit = findings.filter(f => (f.severity === 'critical' || f.severity === 'high') && f.category === 'trivy' && (!fixStates[f.id] || fixStates[f.id].status === 'idle'));

  const handleFixAll = async () => {
    setFixingAll(true);
    for (const f of fixableHighCrit) {
      await handleFix(f);
    }
    setFixingAll(false);
  };

  const sorted = [...findings].sort((a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity));

  if (!open) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4" onClick={onClose}>
      <div className="relative flex max-h-[80vh] w-full max-w-2xl flex-col overflow-hidden rounded-xl border border-[var(--border-subtle)] bg-[var(--surface)] shadow-2xl" onClick={e => e.stopPropagation()}>
        <div className="flex items-center justify-between border-b border-[var(--border-subtle)] px-5 py-4">
          <div>
            <p className="text-sm font-semibold text-[var(--text)]">Security — {username}</p>
            <p className="text-xs text-[var(--text-muted)]">
              {lastRun ? `Last scan ${relativeTime(lastRun.completedAt || lastRun.startedAt)}` : 'No scan yet'}
            </p>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={handleScan}
              disabled={scanning}
              className="flex items-center gap-1.5 rounded-lg border border-[var(--border-subtle)] bg-[var(--surface-2)] px-3 py-1.5 text-xs text-[var(--text-secondary)] transition-colors hover:text-[var(--text)] disabled:opacity-50"
            >
              {scanning ? <Loader2 size={11} className="animate-spin" /> : <RefreshCw size={11} />}
              {scanning ? 'Scanning…' : 'Scan now'}
            </button>
            <button onClick={onClose} className="rounded p-1 text-[var(--text-muted)] hover:text-[var(--text)] hover:bg-[var(--surface-2)]">
              <X size={16} />
            </button>
          </div>
        </div>

        {fixableHighCrit.length > 0 && (
          <div className="flex items-center justify-between border-b border-red-500/20 bg-red-500/5 px-5 py-2.5">
            <p className="text-xs text-red-400">{fixableHighCrit.length} critical/high {fixableHighCrit.length === 1 ? 'vulnerability' : 'vulnerabilities'} with available fixes</p>
            <button
              onClick={handleFixAll}
              disabled={fixingAll}
              className="flex items-center gap-1.5 rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-1.5 text-xs font-medium text-red-400 transition-colors hover:bg-red-500/20 disabled:opacity-50"
            >
              {fixingAll && <Loader2 size={11} className="animate-spin" />}
              Fix all critical &amp; high
            </button>
          </div>
        )}

        <div className="flex-1 overflow-y-auto px-5 py-4">
          {loadingFindings ? (
            <div className="flex items-center justify-center py-12">
              <Loader2 size={20} className="animate-spin text-[var(--text-muted)]" />
            </div>
          ) : sorted.length === 0 ? (
            <div className="flex flex-col items-center justify-center gap-2 py-12 text-center">
              <CheckCircle2 size={24} className="text-emerald-400" />
              <p className="text-sm font-medium text-[var(--text)]">No open findings</p>
              <p className="text-xs text-[var(--text-muted)]">{lastRun ? 'Container looks clean.' : 'Run a scan to check for vulnerabilities.'}</p>
            </div>
          ) : (
            <div className="flex flex-col gap-2">
              {sorted.map(f => {
                const fix = fixStates[f.id] || { status: 'idle' };
                const isDone = fix.status === 'done';
                return (
                  <div key={f.id} className={`flex items-start gap-3 rounded-lg border px-3 py-2.5 text-xs ${isDone ? 'opacity-40' : severityBg(f.severity)}`}>
                    <span className={`mt-0.5 shrink-0 font-semibold uppercase ${severityColor(f.severity)}`} style={{ minWidth: 52 }}>{f.severity}</span>
                    <div className="flex-1 min-w-0">
                      <p className={`font-medium text-[var(--text)] ${isDone ? 'line-through' : ''}`}>{f.title}</p>
                      {f.cveIds && <p className="mt-0.5 font-mono text-[var(--text-muted)]">{f.cveIds}</p>}
                      {fix.status === 'done' && (
                        <p className="mt-0.5 text-emerald-400">{fix.packageName} {fix.oldVersion} → {fix.newVersion}</p>
                      )}
                      {fix.status === 'error' && (
                        <p className="mt-0.5 text-red-400">{fix.message}</p>
                      )}
                    </div>
                    {f.category === 'trivy' && fix.status !== 'done' && (
                      <button
                        onClick={() => handleFix(f)}
                        disabled={fix.status === 'loading'}
                        className="shrink-0 flex items-center gap-1 rounded border border-[var(--border-subtle)] bg-[var(--surface-2)] px-2 py-1 text-[10px] text-[var(--text-secondary)] transition-colors hover:text-[var(--text)] disabled:opacity-50"
                      >
                        {fix.status === 'loading' ? <Loader2 size={9} className="animate-spin" /> : null}
                        Fix
                      </button>
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
