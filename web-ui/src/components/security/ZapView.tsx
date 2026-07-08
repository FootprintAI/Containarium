'use client';

import { useState, useEffect, useCallback } from 'react';
import { Play, RefreshCw, Download, ChevronDown, ChevronUp, EyeOff, Loader2 } from 'lucide-react';
import { Server } from '@/src/types/server';
import { ZapAlert, ZapAlertSummary, ZapScanRun, ZapConfig } from '@/src/types/security';
import { getClient } from '@/src/lib/api/client';
import { Modal, ModalBtn, Textarea, FormField } from '@/src/components/ui/Modal';

interface ZapViewProps { server: Server; }

function formatDate(iso: string): string {
  if (!iso) return '-';
  try { return new Date(iso).toLocaleString(); } catch { return iso; }
}

function RiskBadge({ risk }: { risk: string }) {
  const cls: Record<string, string> = {
    high:          'border-red-500/30 bg-red-500/10 text-[var(--c-red)]',
    medium:        'border-amber-500/30 bg-amber-500/10 text-[var(--c-amber)]',
    low:           'border-blue-500/30 bg-blue-500/10 text-[var(--c-blue)]',
    informational: 'border-[var(--border-subtle)] bg-[var(--surface-2)] text-[var(--text-muted)]',
  };
  return <span className={`rounded-full border px-2 py-0.5 text-[10px] font-medium ${cls[risk] || cls.informational} ${risk === 'high' ? 'font-bold' : ''}`}>{risk}</span>;
}

function StatusBadge({ status }: { status: string }) {
  switch (status) {
    case 'open': return <span className="rounded-full border border-red-500/30 bg-red-500/10 px-2 py-0.5 text-[10px] text-[var(--c-red)]">Open</span>;
    case 'resolved': return <span className="rounded-full border border-emerald-500/30 bg-emerald-500/10 px-2 py-0.5 text-[10px] text-[var(--c-emerald)]">Resolved</span>;
    case 'suppressed': return <span className="rounded-full border border-[var(--border-subtle)] bg-[var(--surface-2)] px-2 py-0.5 text-[10px] text-[var(--text-muted)]">Suppressed</span>;
    default: return <span className="rounded-full border border-[var(--border-subtle)] px-2 py-0.5 text-[10px] text-[var(--text-muted)]">{status}</span>;
  }
}

function SummaryCard({ title, value, color }: { title: string; value: number; color: string }) {
  return (
    <div className="flex min-w-[100px] flex-col items-center rounded-xl border border-[var(--border-subtle)] bg-[var(--surface)] p-3">
      <span className={`text-2xl font-bold ${color}`}>{value}</span>
      <span className="text-[10px] text-[var(--text-muted)]">{title}</span>
    </div>
  );
}

function AlertRow({ alert, onSuppress }: { alert: ZapAlert; onSuppress: (id: number) => void }) {
  const [expanded, setExpanded] = useState(false);
  const TD = 'px-3 py-2 text-xs';

  return (
    <>
      <tr onClick={() => setExpanded(!expanded)} className="cursor-pointer border-b border-[var(--border-subtle)] transition-colors hover:bg-[var(--surface)] last:border-0">
        <td className={TD}>
          <div className="flex items-center gap-1">
            {expanded ? <ChevronUp size={10} /> : <ChevronDown size={10} />}
            <RiskBadge risk={alert.risk} />
          </div>
        </td>
        <td className={TD + ' font-medium text-[var(--text)]'}>{alert.alertName}</td>
        <td className={TD}><span className="block max-w-[280px] truncate font-mono text-[10px] text-[var(--text-secondary)]" title={alert.url}>{alert.url}</span></td>
        <td className={TD}><span className="rounded-full border border-[var(--border-subtle)] bg-[var(--surface-2)] px-2 py-0.5 text-[10px] text-[var(--text-muted)]">{alert.confidence}</span></td>
        <td className={TD}><StatusBadge status={alert.status} /></td>
        <td className={TD + ' whitespace-nowrap text-[var(--text-muted)]'}>{formatDate(alert.lastSeenAt)}</td>
        <td className="px-3 py-2 text-right">
          {alert.status === 'open' && (
            <button title="Suppress alert" onClick={e => { e.stopPropagation(); onSuppress(alert.id); }}
              className="rounded p-1 text-[var(--text-muted)] transition-colors hover:bg-[var(--surface-2)] hover:text-[var(--text)]"><EyeOff size={12} /></button>
          )}
        </td>
      </tr>
      {expanded && (
        <tr className="border-b border-[var(--border-subtle)]">
          <td colSpan={7} className="bg-[var(--surface-2)] px-8 py-3">
            <div className="flex flex-col gap-2 text-xs">
              {alert.description && <div><p className="mb-0.5 text-[10px] text-[var(--text-muted)]">Description</p><p className="text-[var(--text)]">{alert.description}</p></div>}
              {alert.evidence && (
                <div>
                  <p className="mb-0.5 text-[10px] text-[var(--text-muted)]">Evidence</p>
                  <pre className="overflow-x-auto rounded border border-[var(--border-subtle)] bg-[var(--surface)] p-2 font-mono text-[10px] text-[var(--text)] whitespace-pre-wrap">{alert.evidence}</pre>
                </div>
              )}
              {alert.solution && <div><p className="mb-0.5 text-[10px] text-[var(--text-muted)]">Solution</p><p className="text-[var(--text)]">{alert.solution}</p></div>}
              {alert.cweIds && <div><p className="mb-0.5 text-[10px] text-[var(--text-muted)]">CWE IDs</p><code className="font-mono text-[var(--text-secondary)]">{alert.cweIds}</code></div>}
              {alert.references && <div><p className="mb-0.5 text-[10px] text-[var(--text-muted)]">References</p><p className="text-[10px] text-[var(--text-secondary)] whitespace-pre-wrap">{alert.references}</p></div>}
              <div className="flex flex-wrap gap-4 text-[10px] text-[var(--text-muted)]">
                <span>Method: {alert.method || 'GET'}</span>
                <span>Plugin: {alert.pluginId}</span>
                <span>First seen: {formatDate(alert.firstSeenAt)}</span>
                <span>Last seen: {formatDate(alert.lastSeenAt)}</span>
                {alert.resolvedAt && <span>Resolved: {formatDate(alert.resolvedAt)}</span>}
              </div>
            </div>
          </td>
        </tr>
      )}
    </>
  );
}

export default function ZapView({ server }: ZapViewProps) {
  const [summary, setSummary] = useState<ZapAlertSummary | null>(null);
  const [alerts, setAlerts] = useState<ZapAlert[]>([]);
  const [totalCount, setTotalCount] = useState(0);
  const [scanRuns, setScanRuns] = useState<ZapScanRun[]>([]);
  const [config, setConfig] = useState<ZapConfig | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [scanning, setScanning] = useState(false);
  const [snackMessage, setSnackMessage] = useState<string | null>(null);
  const [riskFilter, setRiskFilter] = useState('');
  const [statusFilter, setStatusFilter] = useState('open');
  const [domainInput, setDomainInput] = useState('');
  const [domainFilter, setDomainFilter] = useState('');
  const [page, setPage] = useState(0);
  const [rowsPerPage, setRowsPerPage] = useState(25);
  const [suppressId, setSuppressId] = useState<number | null>(null);
  const [suppressReason, setSuppressReason] = useState('');
  const [showScanHistory, setShowScanHistory] = useState(false);
  const [downloadFormat, setDownloadFormat] = useState<'csv' | 'json'>('csv');
  const [downloading, setDownloading] = useState(false);
  const [installing, setInstalling] = useState(false);

  useEffect(() => {
    if (snackMessage) { const t = setTimeout(() => setSnackMessage(null), 5000); return () => clearTimeout(t); }
  }, [snackMessage]);

  // Debounce the free-text domain filter so it doesn't re-query on every keystroke.
  useEffect(() => {
    const t = setTimeout(() => { setDomainFilter(domainInput.trim()); setPage(0); }, 400);
    return () => clearTimeout(t);
  }, [domainInput]);

  const loadData = useCallback(async () => {
    try {
      const client = getClient(server);
      const limit = rowsPerPage === -1 ? 1000 : rowsPerPage;
      const offset = rowsPerPage === -1 ? 0 : page * rowsPerPage;
      const [summaryResp, alertsResp, runsResp, configResp] = await Promise.all([
        client.getZapAlertSummary(),
        client.listZapAlerts({ risk: riskFilter || undefined, status: statusFilter || undefined, domain: domainFilter || undefined, limit, offset }),
        client.listZapScanRuns(10),
        client.getZapConfig(),
      ]);
      setSummary(summaryResp.summary); setAlerts(alertsResp.alerts); setTotalCount(alertsResp.totalCount);
      setScanRuns(runsResp.scanRuns); setConfig(configResp.config); setError(null);
    } catch (err) { setError(err instanceof Error ? err.message : 'Failed to load ZAP data'); }
    finally { setIsLoading(false); }
  }, [server, riskFilter, statusFilter, domainFilter, page, rowsPerPage]);

  useEffect(() => { loadData(); const interval = setInterval(loadData, 60000); return () => clearInterval(interval); }, [loadData]);

  const handleTriggerScan = async () => {
    setScanning(true);
    try {
      const client = getClient(server);
      const result = await client.triggerZapScan();
      setSnackMessage(result.message || `Scan started: ${result.scanRunId}`);
      const pollInterval = setInterval(async () => {
        try {
          const runsResp = await client.listZapScanRuns(5);
          setScanRuns(runsResp.scanRuns);
          const latest = runsResp.scanRuns[0];
          if (latest && latest.id === result.scanRunId && latest.status !== 'running') { clearInterval(pollInterval); setScanning(false); loadData(); }
        } catch { /* ignore */ }
      }, 10000);
      setTimeout(() => { clearInterval(pollInterval); setScanning(false); }, 1800000);
    } catch (err) { setSnackMessage(err instanceof Error ? err.message : 'Scan trigger failed'); setScanning(false); }
  };

  const handleSuppress = async () => {
    if (suppressId === null) return;
    try {
      const client = getClient(server);
      await client.suppressZapAlert(suppressId, suppressReason);
      setSnackMessage('Alert suppressed'); setSuppressId(null); setSuppressReason(''); loadData();
    } catch (err) { setSnackMessage(err instanceof Error ? err.message : 'Failed to suppress alert'); }
  };

  const handleDownload = async () => {
    setDownloading(true);
    try {
      const client = getClient(server);
      const resp = await client.listZapAlerts({ risk: riskFilter || undefined, status: statusFilter || undefined, domain: domainFilter || undefined, limit: 1000, offset: 0 });
      const all = resp.alerts;
      const dateStr = new Date().toISOString().slice(0, 10);
      let blob: Blob; let filename: string;
      if (downloadFormat === 'json') {
        blob = new Blob([JSON.stringify(all, null, 2)], { type: 'application/json' }); filename = `zap-alerts-${dateStr}.json`;
      } else {
        const cols = ['id', 'risk', 'confidence', 'alertName', 'description', 'url', 'method', 'evidence', 'solution', 'cweIds', 'status', 'firstSeenAt', 'lastSeenAt', 'resolvedAt', 'suppressed', 'suppressedReason'] as const;
        const esc = (v: unknown) => { const s = String(v ?? ''); return s.includes(',') || s.includes('"') || s.includes('\n') ? `"${s.replace(/"/g, '""')}"` : s; };
        blob = new Blob([[cols.join(','), ...all.map(a => cols.map(c => esc(a[c])).join(','))].join('\n')], { type: 'text/csv' });
        filename = `zap-alerts-${dateStr}.csv`;
      }
      const url = URL.createObjectURL(blob); const a = document.createElement('a');
      a.href = url; a.download = filename; document.body.appendChild(a); a.click(); document.body.removeChild(a); URL.revokeObjectURL(url);
    } catch (err) { setSnackMessage(err instanceof Error ? err.message : 'Download failed'); }
    finally { setDownloading(false); }
  };

  const handleDownloadReport = async (scanRunId: string) => {
    try {
      const client = getClient(server);
      const report = await client.getZapReport(scanRunId, 'html');
      const blob = new Blob([report.content], { type: report.contentType || 'text/html' });
      const url = URL.createObjectURL(blob); const a = document.createElement('a');
      a.href = url; a.download = report.filename || `zap-report-${scanRunId}.html`;
      document.body.appendChild(a); a.click(); document.body.removeChild(a); URL.revokeObjectURL(url);
    } catch (err) { setSnackMessage(err instanceof Error ? err.message : 'Failed to download report'); }
  };

  const handleInstallZap = async () => {
    setInstalling(true);
    try {
      const client = getClient(server);
      const result = await client.installZap();
      setSnackMessage(result.message || 'ZAP installed');
      if (result.success) loadData();
    } catch (err) { setSnackMessage(err instanceof Error ? err.message : 'Failed to install ZAP'); }
    finally { setInstalling(false); }
  };

  const selectCls = 'appearance-none rounded-md border border-[var(--border-subtle)] bg-[var(--surface-2)] px-3 py-1.5 text-xs text-[var(--text)] focus:border-[var(--accent)] focus:outline-none';
  const totalPages = Math.ceil(totalCount / rowsPerPage);

  if (isLoading) return <div className="flex justify-center py-16"><Loader2 size={20} className="animate-spin text-[var(--text-secondary)]" /></div>;
  if (error) return (
    <div className="flex items-center gap-2 rounded-lg border border-red-500/30 bg-red-500/10 p-3 text-xs text-[var(--c-red)]">
      {error}
      <button onClick={loadData} className="ml-auto rounded p-1 hover:bg-red-500/20"><RefreshCw size={12} /></button>
    </div>
  );

  return (
    <div className="flex flex-col gap-4">
      {/* Header */}
      <div className="flex items-start justify-between gap-3">
        <div>
          <h2 className="text-sm font-semibold text-[var(--text)]">OWASP ZAP Web Application Scan</h2>
          {config && (
            <div className="mt-1 flex flex-wrap items-center gap-2">
              <span className="text-[10px] text-[var(--text-muted)]">
                Interval: {config.interval}{config.zapAvailable && config.zapVersion && ` | ZAP: ${config.zapVersion}`}{config.zapAvailable && !config.zapVersion && ' | ZAP: installed'}
              </span>
              {!config.zapAvailable && (
                <button onClick={handleInstallZap} disabled={installing}
                  className="flex items-center gap-1 rounded border border-[var(--border-subtle)] px-2 py-0.5 text-[10px] text-[var(--text-secondary)] hover:bg-[var(--surface-2)] disabled:opacity-50">
                  {installing ? <Loader2 size={10} className="animate-spin" /> : <Download size={10} />} Install ZAP
                </button>
              )}
            </div>
          )}
        </div>
        <div className="flex items-center gap-2">
          <button onClick={handleTriggerScan} disabled={scanning || (config !== null && !config.zapAvailable)}
            className="flex items-center gap-1.5 rounded-md bg-[var(--accent)] px-3 py-1.5 text-xs text-white hover:bg-[var(--accent-hover)] disabled:opacity-50">
            {scanning ? <Loader2 size={12} className="animate-spin" /> : <Play size={12} />} Run Scan
          </button>
          <button onClick={loadData} className="rounded-md border border-[var(--border-subtle)] bg-[var(--surface)] p-1.5 text-[var(--text-muted)] hover:bg-[var(--surface-2)]"><RefreshCw size={12} /></button>
        </div>
      </div>

      {/* Scan Progress */}
      {scanRuns.length > 0 && scanRuns[0].status === 'running' && (
        <div>
          <p className="mb-1 text-xs text-[var(--text-muted)]">Scanning... {scanRuns[0].completedCount}/{scanRuns[0].targetsCount} targets</p>
          <div className="h-1.5 w-full overflow-hidden rounded-full bg-[var(--surface-2)]">
            <div className="h-1.5 rounded-full bg-[var(--accent)]" style={{ width: `${scanRuns[0].targetsCount > 0 ? (scanRuns[0].completedCount / scanRuns[0].targetsCount) * 100 : 0}%` }} />
          </div>
        </div>
      )}

      {/* Summary Cards */}
      {summary && (
        <div className="flex flex-wrap gap-2">
          <SummaryCard title="Open" value={summary.openAlerts} color="text-[var(--c-red)]" />
          <SummaryCard title="High" value={summary.highCount} color="text-red-500" />
          <SummaryCard title="Medium" value={summary.mediumCount} color="text-[var(--c-amber)]" />
          <SummaryCard title="Low" value={summary.lowCount} color="text-[var(--c-blue)]" />
          <SummaryCard title="Info" value={summary.infoCount} color="text-[var(--text-muted)]" />
          <SummaryCard title="Resolved" value={summary.resolvedAlerts} color="text-[var(--c-emerald)]" />
          <SummaryCard title="Suppressed" value={summary.suppressedAlerts} color="text-[var(--text-muted)]" />
        </div>
      )}

      {/* Filters */}
      <div className="flex flex-wrap items-center gap-3 rounded-xl border border-[var(--border-subtle)] bg-[var(--surface)] p-4">
        <select value={riskFilter} onChange={e => { setRiskFilter(e.target.value); setPage(0); }} className={selectCls}>
          <option value="">All Risk Levels</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
          <option value="informational">Informational</option>
        </select>
        <select value={statusFilter} onChange={e => { setStatusFilter(e.target.value); setPage(0); }} className={selectCls}>
          <option value="">All Statuses</option>
          <option value="open">Open</option>
          <option value="resolved">Resolved</option>
          <option value="suppressed">Suppressed</option>
        </select>
        <input type="text" value={domainInput} onChange={e => setDomainInput(e.target.value)} placeholder="Filter by domain..."
          className="rounded-md border border-[var(--border-subtle)] bg-[var(--surface-2)] px-3 py-1.5 text-xs text-[var(--text)] placeholder:text-[var(--text-muted)] focus:border-[var(--accent)] focus:outline-none" style={{ width: 180 }} />
        <span className="text-xs text-[var(--text-muted)]">{totalCount} alerts</span>
        <div className="ml-auto flex items-center gap-2">
          <select value={downloadFormat} onChange={e => setDownloadFormat(e.target.value as 'csv' | 'json')} className={selectCls} style={{ width: 70 }}>
            <option value="csv">CSV</option>
            <option value="json">JSON</option>
          </select>
          <button onClick={handleDownload} disabled={downloading || totalCount === 0}
            className="flex items-center gap-1.5 rounded-md border border-[var(--border-subtle)] bg-[var(--surface)] px-3 py-1.5 text-xs text-[var(--text-secondary)] hover:bg-[var(--surface-2)] disabled:opacity-50">
            {downloading ? <Loader2 size={12} className="animate-spin" /> : <Download size={12} />} Download
          </button>
        </div>
      </div>

      {/* Alerts Table */}
      <div className="overflow-x-auto rounded-xl border border-[var(--border-subtle)]">
        <table className="w-full text-xs">
          <thead>
            <tr className="border-b border-[var(--border-subtle)] bg-[var(--surface)]">
              {['Risk', 'Alert', 'URL', 'Confidence', 'Status', 'Last Seen', ''].map(h => (
                <th key={h} className="px-3 py-2.5 text-left text-xs font-medium text-[var(--text-secondary)] whitespace-nowrap">{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {alerts.length === 0 ? (
              <tr><td colSpan={7} className="py-10 text-center text-[var(--text-muted)]">
                {statusFilter === 'open' ? 'No open ZAP alerts.' : 'No alerts match the current filters.'}
              </td></tr>
            ) : (
              alerts.map(alert => <AlertRow key={alert.id} alert={alert} onSuppress={id => setSuppressId(id)} />)
            )}
          </tbody>
        </table>
        {totalCount > 0 && (
          <div className="flex items-center justify-between border-t border-[var(--border-subtle)] px-4 py-2 text-xs text-[var(--text-muted)]">
            <div className="flex items-center gap-2">
              <span>Rows:</span>
              <select value={rowsPerPage} onChange={e => { setRowsPerPage(parseInt(e.target.value)); setPage(0); }}
                className="rounded border border-[var(--border-subtle)] bg-[var(--surface-2)] px-2 py-0.5 text-xs text-[var(--text)] focus:outline-none">
                {[10, 25, 50, 100].map(n => <option key={n} value={n}>{n}</option>)}
              </select>
            </div>
            <div className="flex items-center gap-2">
              <span>{page * rowsPerPage + 1}–{Math.min((page + 1) * rowsPerPage, totalCount)} of {totalCount}</span>
              <button onClick={() => setPage(page - 1)} disabled={page === 0} className="rounded px-2 py-1 hover:bg-[var(--surface-2)] disabled:opacity-40">‹</button>
              <button onClick={() => setPage(page + 1)} disabled={page >= totalPages - 1} className="rounded px-2 py-1 hover:bg-[var(--surface-2)] disabled:opacity-40">›</button>
            </div>
          </div>
        )}
      </div>

      {/* Scan History */}
      <button onClick={() => setShowScanHistory(!showScanHistory)} className="flex items-center gap-1.5 text-xs text-[var(--text-muted)] hover:text-[var(--text-secondary)]">
        {showScanHistory ? <ChevronUp size={12} /> : <ChevronDown size={12} />} Scan History ({scanRuns.length})
      </button>
      {showScanHistory && (
        <div className="overflow-x-auto rounded-xl border border-[var(--border-subtle)]">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-[var(--border-subtle)] bg-[var(--surface)]">
                {['Started', 'Trigger', 'Status', 'Targets', 'High', 'Medium', 'Low', 'Duration', ''].map(h => (
                  <th key={h} className="px-3 py-2.5 text-left text-xs font-medium text-[var(--text-secondary)] whitespace-nowrap">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {scanRuns.map(run => (
                <tr key={run.id} className="border-b border-[var(--border-subtle)] transition-colors hover:bg-[var(--surface)] last:border-0">
                  <td className="px-3 py-2 text-xs text-[var(--text-muted)] whitespace-nowrap">{formatDate(run.startedAt)}</td>
                  <td className="px-3 py-2 text-xs"><span className="rounded-full border border-[var(--border-subtle)] bg-[var(--surface-2)] px-2 py-0.5 text-[10px] text-[var(--text-muted)]">{run.trigger}</span></td>
                  <td className="px-3 py-2 text-xs">
                    <span className={`rounded-full border px-2 py-0.5 text-[10px] ${run.status === 'completed' ? 'border-emerald-500/30 bg-emerald-500/10 text-[var(--c-emerald)]' : run.status === 'failed' ? 'border-red-500/30 bg-red-500/10 text-[var(--c-red)]' : 'border-blue-500/30 bg-blue-500/10 text-[var(--c-blue)]'}`}>{run.status}</span>
                  </td>
                  <td className="px-3 py-2 text-xs text-[var(--text-secondary)]">{run.targetsCount}</td>
                  <td className="px-3 py-2 text-xs">{run.highCount > 0 ? <span className="font-bold text-[var(--c-red)]">{run.highCount}</span> : <span className="text-[var(--text-muted)]">-</span>}</td>
                  <td className="px-3 py-2 text-xs">{run.mediumCount > 0 ? <span className="text-[var(--c-amber)]">{run.mediumCount}</span> : <span className="text-[var(--text-muted)]">-</span>}</td>
                  <td className="px-3 py-2 text-xs">{run.lowCount > 0 ? run.lowCount : <span className="text-[var(--text-muted)]">-</span>}</td>
                  <td className="px-3 py-2 text-xs text-[var(--text-muted)]">{run.duration || '-'}</td>
                  <td className="px-3 py-2 text-right">
                    {run.status === 'completed' && (
                      <button title="Download HTML report" onClick={() => handleDownloadReport(run.id)}
                        className="rounded p-1 text-[var(--text-muted)] transition-colors hover:bg-[var(--surface-2)] hover:text-[var(--text)]"><Download size={12} /></button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Suppress Dialog */}
      <Modal open={suppressId !== null} onClose={() => { setSuppressId(null); setSuppressReason(''); }} title="Suppress ZAP Alert" size="sm"
        footer={
          <>
            <ModalBtn onClick={() => { setSuppressId(null); setSuppressReason(''); }}>Cancel</ModalBtn>
            <ModalBtn variant="primary" onClick={handleSuppress}>Suppress</ModalBtn>
          </>
        }>
        <p className="mb-3 text-xs text-[var(--text-muted)]">Suppressed alerts are excluded from open counts and alerts.</p>
        <FormField label="Reason">
          <Textarea value={suppressReason} onChange={e => setSuppressReason(e.target.value)} placeholder="e.g., Accepted risk, false positive, handled externally" rows={2} />
        </FormField>
      </Modal>

      {snackMessage && (
        <div onClick={() => setSnackMessage(null)} className="fixed bottom-4 left-1/2 z-50 -translate-x-1/2 cursor-pointer rounded-lg border border-[var(--border)] bg-[var(--surface-2)] px-4 py-2.5 text-xs text-[var(--text)] shadow-xl">
          {snackMessage}
        </div>
      )}
    </div>
  );
}
