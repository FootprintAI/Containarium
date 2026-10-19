'use client';

import { useState, useMemo, useEffect, useRef, useCallback } from 'react';
import { Shield, Bug, Scan, RefreshCw, Download, ChevronDown, ChevronUp, Loader2, Timer, CheckCircle2, AlertCircle, ScanLine } from 'lucide-react';
import { Server } from '@/src/types/server';
import { ClamavContainerSummary, ClamavReport, ScanStatusResponse } from '@/src/types/security';
import { useSecurity } from '@/src/lib/hooks/useSecurity';
import { getClient } from '@/src/lib/api/client';
import PentestView from './PentestView';
import ZapView from './ZapView';

interface SecurityViewProps { server: Server; }

function formatDate(iso: string): string {
  if (!iso) return 'Never';
  try { return new Date(iso).toLocaleString(); } catch { return iso; }
}

function StatusBadge({ status }: { status: string }) {
  switch (status) {
    case 'clean': return <span className="rounded-full border border-emerald-500/30 bg-emerald-500/10 px-2 py-0.5 text-[10px] text-[var(--c-emerald)]">Clean</span>;
    case 'infected': return <span className="rounded-full border border-red-500/30 bg-red-500/10 px-2 py-0.5 text-[10px] text-[var(--c-red)]">Infected</span>;
    case 'never': return <span className="rounded-full border border-[var(--border-subtle)] bg-[var(--surface-2)] px-2 py-0.5 text-[10px] text-[var(--text-muted)]">Never Scanned</span>;
    default: return <span className="rounded-full border border-[var(--border-subtle)] bg-[var(--surface-2)] px-2 py-0.5 text-[10px] text-[var(--text-muted)]">{status}</span>;
  }
}

function SummaryCard({ title, value, color }: { title: string; value: number; color: string }) {
  return (
    <div className="flex min-w-[130px] flex-col items-center rounded-xl border border-[var(--border-subtle)] bg-[var(--surface)] p-3">
      <span className={`text-2xl font-bold ${color}`}>{value}</span>
      <span className="text-[10px] text-[var(--text-muted)]">{title}</span>
    </div>
  );
}

function ContainerScanAction({ containerName, scanStatus, onScan }: { containerName: string; scanStatus: ScanStatusResponse | null; onScan: (name: string) => void }) {
  const job = scanStatus?.jobs?.find(j => j.containerName === containerName && (j.status === 'pending' || j.status === 'running'));
  if (job?.status === 'pending') return <span title="Queued — waiting for available worker"><Timer size={14} className="text-[var(--text-muted)]" /></span>;
  if (job?.status === 'running') return <Loader2 size={14} className="animate-spin text-[var(--text-secondary)]" />;
  const recentJob = scanStatus?.jobs?.find(j => j.containerName === containerName);
  if (recentJob?.status === 'failed') return (
    <button title={`Failed: ${recentJob.errorMessage || 'unknown error'}`} onClick={e => { e.stopPropagation(); onScan(containerName); }}
      className="rounded p-1 text-[var(--c-red)] hover:bg-red-500/10"><AlertCircle size={13} /></button>
  );
  if (recentJob?.status === 'completed') return (
    <button title="Scan completed — click to re-scan" onClick={e => { e.stopPropagation(); onScan(containerName); }}
      className="rounded p-1 text-[var(--c-emerald)] hover:bg-emerald-500/10"><CheckCircle2 size={13} /></button>
  );
  return (
    <button title="Trigger scan" onClick={e => { e.stopPropagation(); onScan(containerName); }}
      className="rounded p-1 text-[var(--text-muted)] transition-colors hover:bg-[var(--surface-2)] hover:text-[var(--text)]"><ScanLine size={13} /></button>
  );
}

function ContainerRow({ container, server, onScan, scanStatus }: { container: ClamavContainerSummary; server: Server; onScan: (name: string) => void; scanStatus: ScanStatusResponse | null }) {
  const [expanded, setExpanded] = useState(false);
  const [history, setHistory] = useState<ClamavReport[]>([]);
  const [historyLoading, setHistoryLoading] = useState(false);

  const loadHistory = async () => {
    if (history.length > 0) { setExpanded(!expanded); return; }
    setHistoryLoading(true);
    try {
      const client = getClient(server);
      const result = await client.listClamavReports({ containerName: container.containerName, limit: 20 });
      setHistory(result.reports); setExpanded(true);
    } catch { /* ignore */ }
    finally { setHistoryLoading(false); }
  };

  const TD = 'px-3 py-2 text-xs text-[var(--text-secondary)]';

  return (
    <>
      <tr onClick={loadHistory} className="cursor-pointer border-b border-[var(--border-subtle)] transition-colors hover:bg-[var(--surface)] last:border-0">
        <td className={TD}>
          <div className="flex items-center gap-1.5">
            {historyLoading ? <Loader2 size={12} className="animate-spin" /> : expanded ? <ChevronUp size={12} /> : <ChevronDown size={12} />}
            <span className="font-medium text-[var(--text)]">{container.containerName}</span>
          </div>
        </td>
        <td className={TD + ' text-[var(--text-muted)]'}>{container.backendId || 'local'}</td>
        <td className={TD}>{container.username}</td>
        <td className={TD + ' whitespace-nowrap text-[var(--text-muted)]'}>{formatDate(container.lastScanAt)}</td>
        <td className={TD}><StatusBadge status={container.lastStatus} /></td>
        <td className={TD + ' text-right'}>{container.lastFindingsCount}</td>
        <td className={TD + ' text-right'}>{container.totalScans}</td>
        <td className="px-3 py-2 text-right">
          <ContainerScanAction containerName={container.containerName} scanStatus={scanStatus} onScan={onScan} />
        </td>
      </tr>
      {expanded && (
        <tr className="border-b border-[var(--border-subtle)]">
          <td colSpan={8} className="bg-[var(--surface-2)] px-6 py-3">
            {history.length === 0 ? (
              <p className="text-xs text-[var(--text-muted)]">No scan history</p>
            ) : (
              <table className="w-full text-xs">
                <thead>
                  <tr className="border-b border-[var(--border-subtle)]">
                    {['Scanned At', 'Status', 'Findings', 'Duration'].map(h => (
                      <th key={h} className="pb-2 text-left text-[10px] font-medium text-[var(--text-muted)]">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {history.map(report => (
                    <tr key={report.id} className="border-b border-[var(--border-subtle)] last:border-0">
                      <td className="py-1.5 pr-4 text-[var(--text-muted)] whitespace-nowrap">{formatDate(report.scannedAt)}</td>
                      <td className="py-1.5 pr-4"><StatusBadge status={report.status} /></td>
                      <td className="py-1.5 pr-4">
                        {report.findingsCount > 0 ? (
                          <pre className="font-mono text-[10px] text-[var(--text)] whitespace-pre-wrap">{report.findings}</pre>
                        ) : <span className="text-[var(--text-muted)]">None</span>}
                      </td>
                      <td className="py-1.5 text-[var(--text-muted)]">{report.scanDuration}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </td>
        </tr>
      )}
    </>
  );
}

function ClamavView({ server }: SecurityViewProps) {
  const { summary, isLoading, error, refresh } = useSecurity(server);
  const [scanningContainer, setScanningContainer] = useState<string | null>(null);
  const [snackMessage, setSnackMessage] = useState<string | null>(null);
  const [scanStatus, setScanStatus] = useState<ScanStatusResponse | null>(null);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const [exportFrom, setExportFrom] = useState(() => new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString().slice(0, 10));
  const [exportTo, setExportTo] = useState(() => new Date().toISOString().slice(0, 10));

  useEffect(() => {
    if (snackMessage) { const t = setTimeout(() => setSnackMessage(null), 5000); return () => clearTimeout(t); }
  }, [snackMessage]);

  const stopPolling = useCallback(() => { if (pollRef.current) { clearInterval(pollRef.current); pollRef.current = null; } }, []);

  const startPolling = useCallback(() => {
    stopPolling();
    const client = getClient(server);
    const poll = async () => {
      try {
        const status = await client.getScanStatus();
        setScanStatus(status);
        if (status.pendingCount === 0 && status.runningCount === 0) { stopPolling(); setScanningContainer(null); refresh(); }
      } catch { /* ignore */ }
    };
    poll();
    pollRef.current = setInterval(poll, 5000);
  }, [server, stopPolling, refresh]);

  useEffect(() => () => stopPolling(), [stopPolling]);

  const handleScanContainer = async (containerName: string) => {
    setScanningContainer(containerName);
    try {
      const client = getClient(server);
      const result = await client.triggerClamavScan(containerName);
      setSnackMessage(result.message || `Scan queued for ${containerName}`); startPolling();
    } catch (err) { setSnackMessage(err instanceof Error ? err.message : 'Scan failed'); setScanningContainer(null); }
  };

  const isScanning = !!scanningContainer;

  const sortedContainers = useMemo(() => {
    if (!summary?.containers) return [];
    const order: Record<string, number> = { infected: 0, never: 1, clean: 2 };
    return [...summary.containers].sort((a, b) => (order[a.lastStatus] ?? 3) - (order[b.lastStatus] ?? 3));
  }, [summary?.containers]);

  const inputCls = 'rounded-md border border-[var(--border-subtle)] bg-[var(--surface-2)] px-3 py-1.5 text-xs text-[var(--text)] focus:border-[var(--accent)] focus:outline-none';

  if (isLoading) return <div className="flex justify-center py-16"><Loader2 size={20} className="animate-spin text-[var(--text-secondary)]" /></div>;
  if (error) return (
    <div className="flex items-center gap-2 rounded-lg border border-red-500/30 bg-red-500/10 p-3 text-xs text-[var(--c-red)]">
      {error instanceof Error ? error.message : 'Failed to fetch security data'}
      <button onClick={refresh} className="ml-auto rounded p-1 hover:bg-red-500/20"><RefreshCw size={12} /></button>
    </div>
  );

  return (
    <div className="flex flex-col gap-4">
      {/* Header */}
      <div className="flex items-center gap-3">
        <h2 className="mr-auto text-sm font-semibold text-[var(--text)]">ClamAV Malware Scanning</h2>
        <button onClick={refresh} className="rounded-md border border-[var(--border-subtle)] bg-[var(--surface)] p-1.5 text-[var(--text-muted)] transition-colors hover:bg-[var(--surface-2)]">
          <RefreshCw size={12} />
        </button>
      </div>

      {/* Summary Cards */}
      <div className="flex flex-wrap gap-3">
        <SummaryCard title="Total Containers" value={summary?.totalContainers || 0} color="text-[var(--text)]" />
        <SummaryCard title="Clean" value={summary?.cleanContainers || 0} color="text-[var(--c-emerald)]" />
        <SummaryCard title="Infected" value={summary?.infectedContainers || 0} color="text-[var(--c-red)]" />
        <SummaryCard title="Never Scanned" value={summary?.neverScannedContainers || 0} color="text-[var(--text-muted)]" />
      </div>

      {/* Scan Progress */}
      {isScanning && scanStatus && (scanStatus.pendingCount > 0 || scanStatus.runningCount > 0) && (
        <div className="rounded-xl border border-[var(--border-subtle)] bg-[var(--surface)] p-4">
          <p className="mb-2 text-xs font-medium text-[var(--text)]">Scan Progress</p>
          <div className="mb-2 h-1.5 w-full overflow-hidden rounded-full bg-[var(--surface-2)]">
            <div className="h-1.5 rounded-full bg-[var(--accent)] transition-all" style={{
              width: `${scanStatus.completedCount + scanStatus.failedCount + scanStatus.runningCount + scanStatus.pendingCount > 0
                ? ((scanStatus.completedCount + scanStatus.failedCount) / (scanStatus.completedCount + scanStatus.failedCount + scanStatus.runningCount + scanStatus.pendingCount)) * 100
                : 0}%`
            }} />
          </div>
          <div className="flex gap-4 text-[10px]">
            <span className="text-[var(--text-muted)]">Pending: {scanStatus.pendingCount}</span>
            <span className="text-[var(--c-blue)]">Running: {scanStatus.runningCount}</span>
            <span className="text-[var(--c-emerald)]">Completed: {scanStatus.completedCount}</span>
            {scanStatus.failedCount > 0 && <span className="text-[var(--c-red)]">Failed: {scanStatus.failedCount}</span>}
          </div>
        </div>
      )}

      {/* Export */}
      <div className="flex flex-wrap items-end gap-3 rounded-xl border border-[var(--border-subtle)] bg-[var(--surface)] p-4">
        <p className="w-full text-xs font-medium text-[var(--text)]">Download Scan Reports</p>
        <div className="flex flex-col gap-1">
          <label className="text-[10px] text-[var(--text-muted)]">Start Date</label>
          <input type="date" value={exportFrom} onChange={e => setExportFrom(e.target.value)} className={inputCls} />
        </div>
        <div className="flex flex-col gap-1">
          <label className="text-[10px] text-[var(--text-muted)]">End Date</label>
          <input type="date" value={exportTo} onChange={e => setExportTo(e.target.value)} className={inputCls} />
        </div>
        <button onClick={() => { const client = getClient(server); window.open(client.getClamavReportExportUrl(exportFrom, exportTo), '_blank'); }}
          className="flex items-center gap-1.5 rounded-md bg-[var(--accent)] px-3 py-1.5 text-xs text-white hover:bg-[var(--accent-hover)]">
          <Download size={12} /> Download CSV
        </button>
      </div>

      {/* Container Table */}
      <div className="overflow-x-auto rounded-xl border border-[var(--border-subtle)]">
        <table className="w-full text-xs">
          <thead>
            <tr className="border-b border-[var(--border-subtle)] bg-[var(--surface)]">
              {['Container', 'Node', 'Username', 'Last Scan', 'Status', 'Findings', 'Total Scans', ''].map((h, i) => (
                <th key={h} className={`px-3 py-2.5 text-xs font-medium text-[var(--text-secondary)] whitespace-nowrap ${i >= 5 ? 'text-right' : 'text-left'}`}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {sortedContainers.length === 0 ? (
              <tr><td colSpan={8} className="py-10 text-center text-[var(--text-muted)]">No containers found. The security scanner runs every 24 hours.</td></tr>
            ) : (
              sortedContainers.map(container => (
                <ContainerRow key={container.containerName} container={container} server={server} onScan={handleScanContainer} scanStatus={scanStatus} />
              ))
            )}
          </tbody>
        </table>
      </div>

      {summary?.lastCollectionAt && (
        <p className="text-[10px] text-[var(--text-muted)]">Summary generated at: {formatDate(summary.lastCollectionAt)}</p>
      )}

      {snackMessage && (
        <div onClick={() => setSnackMessage(null)} className="fixed bottom-4 left-1/2 z-50 -translate-x-1/2 cursor-pointer rounded-lg border border-[var(--border)] bg-[var(--surface-2)] px-4 py-2.5 text-xs text-[var(--text)] shadow-xl">
          {snackMessage}
        </div>
      )}
    </div>
  );
}

export default function SecurityView({ server }: SecurityViewProps) {
  const [securityTab, setSecurityTab] = useState(0);

  const TABS = [
    { label: 'Malware Scan', icon: <Shield size={13} /> },
    { label: 'Pentest', icon: <Bug size={13} /> },
    { label: 'ZAP Scan', icon: <Scan size={13} /> },
  ];

  return (
    <div className="p-6">
      {/* Sub-tabs */}
      <div className="mb-6 flex border-b border-[var(--border-subtle)]">
        {TABS.map((tab, i) => (
          <button key={tab.label} onClick={() => setSecurityTab(i)}
            className={`-mb-px flex items-center gap-1.5 px-4 py-2 text-xs font-medium transition-colors ${securityTab === i ? 'border-b-2 border-[var(--accent)] text-[var(--accent)]' : 'text-[var(--text-muted)] hover:text-[var(--text-secondary)]'}`}>
            {tab.icon}{tab.label}
          </button>
        ))}
      </div>
      {securityTab === 0 && <ClamavView server={server} />}
      {securityTab === 1 && <PentestView server={server} />}
      {securityTab === 2 && <ZapView server={server} />}
    </div>
  );
}
