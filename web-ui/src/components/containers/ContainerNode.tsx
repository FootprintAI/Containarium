'use client';

import {
  Trash2, Play, Square, Terminal, Monitor,
  Shield, Tag, SlidersHorizontal, Network, Moon, ShieldAlert,
} from 'lucide-react';
import { Container, ContainerState, ContainerMetricsWithRate } from '@/src/types/container';
import { SecurityBadge } from '@/src/lib/hooks/useSecurity';

interface ContainerNodeProps {
  container: Container;
  metrics?: ContainerMetricsWithRate;
  securityBadge?: SecurityBadge | null;
  onDelete: (username: string) => void;
  onStart?: (username: string) => void;
  onStop?: (username: string) => void;
  onTerminal?: (username: string) => void;
  onEditFirewall?: (username: string) => void;
  onEditLabels?: (username: string) => void;
  onResize?: (username: string) => void;
  onToggleAutoSleep?: (username: string, current: { enabled: boolean; threshold: number }) => void;
  onSecurityClick?: () => void;
}

function parseSize(s: string): number {
  if (!s) return 0;
  const m = s.match(/^([\d.]+)\s*(B|KB|MB|GB|TB|K|M|G|T)?$/i);
  if (!m) return 0;
  const v = parseFloat(m[1]);
  const u = (m[2] || 'B').toUpperCase();
  const mul: Record<string, number> = { B: 1, K: 1024, KB: 1024, M: 1048576, MB: 1048576, G: 1073741824, GB: 1073741824, T: 1099511627776, TB: 1099511627776 };
  return v * (mul[u] || 1);
}

function formatBytes(b: number): string {
  if (b === 0) return '0 B';
  const k = 1024, sz = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(b) / Math.log(k));
  return parseFloat((b / Math.pow(k, i)).toFixed(1)) + ' ' + sz[i];
}

function stateBadge(state: ContainerState) {
  switch (state) {
    case 'Running':     return 'bg-emerald-500/15 text-[var(--c-emerald)] border-emerald-500/30';
    case 'Stopped':     return 'bg-red-500/15 text-[var(--c-red)] border-red-500/30';
    case 'Frozen':
    case 'Creating':
    case 'Provisioning': return 'bg-amber-500/15 text-[var(--c-amber)] border-amber-500/30';
    default:            return 'bg-zinc-500/15 text-zinc-400 border-zinc-500/30';
  }
}

function UsageBar({ used, total, color }: { used: number; total: number; color: string }) {
  const pct = total > 0 ? Math.min((used / total) * 100, 100) : 0;
  return (
    <div className="h-1 w-full rounded-full bg-zinc-800 overflow-hidden">
      <div className={`h-full rounded-full transition-all ${color}`} style={{ width: `${pct}%` }} />
    </div>
  );
}

function barColor(pct: number) {
  if (pct > 80) return 'bg-red-500';
  if (pct > 60) return 'bg-amber-500';
  return 'bg-emerald-500';
}

function SecurityBadgePill({ badge }: { badge: SecurityBadge }) {
  const total = badge.critical + badge.high;
  if (total > 0) return (
    <span title={`${badge.critical} critical, ${badge.high} high CVEs`}
      className="inline-flex items-center gap-0.5 rounded-full border border-red-500/30 bg-red-500/15 px-1.5 py-0.5 text-[10px] font-medium text-red-400">
      <ShieldAlert size={9} />
      {total}
    </span>
  );
  if (badge.medium > 0) return (
    <span title={`${badge.medium} medium CVEs`}
      className="inline-flex items-center gap-0.5 rounded-full border border-amber-500/30 bg-amber-500/15 px-1.5 py-0.5 text-[10px] font-medium text-amber-400">
      <ShieldAlert size={9} />
      {badge.medium}
    </span>
  );
  return null;
}

function IconBtn({ title, onClick, className = '', children }: { title: string; onClick: () => void; className?: string; children: React.ReactNode }) {
  return (
    <button
      title={title}
      onClick={onClick}
      className={`rounded p-1 text-[var(--text-muted)] transition-colors hover:text-[var(--text)] hover:bg-[var(--surface-2)] ${className}`}
    >
      {children}
    </button>
  );
}

export default function ContainerNode({ container, metrics, securityBadge, onDelete, onStart, onStop, onTerminal, onEditFirewall, onEditLabels, onResize, onToggleAutoSleep, onSecurityClick }: ContainerNodeProps) {
  const isRunning = container.state === 'Running';
  const username = container.username || container.name;

  const cpuCores = parseInt(container.cpu) || 0;
  const cpuUsagePct = metrics?.cpuUsagePercent || 0;
  const cpuNorm = cpuCores > 0 ? Math.min((cpuUsagePct / (cpuCores * 100)) * 100, 100) : 0;

  const memLimit = parseSize(container.memory);
  const diskLimit = parseSize(container.disk);
  const memUsed = metrics?.memoryUsageBytes || 0;
  const diskUsed = metrics?.diskUsageBytes || 0;
  const memPct = memLimit > 0 ? Math.min((memUsed / memLimit) * 100, 100) : 0;
  const diskPct = diskLimit > 0 ? Math.min((diskUsed / diskLimit) * 100, 100) : 0;

  return (
    <div className="flex flex-col gap-3 rounded-xl border border-[var(--border-subtle)] bg-[var(--surface)] p-4 shadow-sm transition-shadow hover:shadow-md hover:border-[var(--border)]">
      {/* Header */}
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0">
          <p className="truncate text-sm font-semibold text-[var(--text)]">{username}</p>
          <p className="truncate text-xs text-[var(--text-muted)]">{container.image || 'ubuntu:24.04'}</p>
        </div>
        {container.state === 'Stopped' && container.autoSleepEnabled ? (
          <span className="shrink-0 inline-flex items-center gap-1 rounded-full border border-indigo-500/30 bg-indigo-500/15 px-2 py-0.5 text-[10px] font-medium text-indigo-400">
            <Moon size={10} />
            Sleeping
          </span>
        ) : (
          <span className={`shrink-0 rounded-full border px-2 py-0.5 text-[10px] font-medium ${stateBadge(container.state)}`}>
            {container.state}
          </span>
        )}
      </div>

      {/* IP + chips */}
      <div className="flex flex-wrap items-center gap-1.5">
        {container.ipAddress && (
          <span className="flex items-center gap-1 rounded bg-[var(--surface-2)] px-1.5 py-0.5 font-mono text-[11px] text-[var(--text-secondary)]">
            <Network size={10} />
            {container.ipAddress}
          </span>
        )}
        {container.gpu && (
          <span className="rounded border border-violet-500/30 bg-violet-500/10 px-1.5 py-0.5 text-[10px] text-[var(--c-violet)]">
            GPU: {container.gpu}
          </span>
        )}
        {container.backendId && (
          <span className={`rounded border px-1.5 py-0.5 text-[10px] ${container.backendId.startsWith('tunnel-') ? 'border-indigo-500/30 bg-indigo-500/10 text-indigo-400' : 'border-blue-500/30 bg-blue-500/10 text-[var(--c-blue)]'}`}>
            {container.backendId}
          </span>
        )}
        {securityBadge && (
          onSecurityClick
            ? <button onClick={onSecurityClick} className="focus:outline-none"><SecurityBadgePill badge={securityBadge} /></button>
            : <SecurityBadgePill badge={securityBadge} />
        )}
      </div>

      {/* Resource bars */}
      {isRunning && (
        <div className="flex flex-col gap-2">
          {container.cpu && (
            <div>
              <div className="mb-1 flex justify-between text-[10px] text-[var(--text-muted)]">
                <span>CPU</span>
                <span>{cpuUsagePct.toFixed(1)}% / {cpuCores}c</span>
              </div>
              <UsageBar used={cpuNorm} total={100} color={barColor(cpuNorm)} />
            </div>
          )}
          {container.memory && memLimit > 0 && (
            <div>
              <div className="mb-1 flex justify-between text-[10px] text-[var(--text-muted)]">
                <span>Memory</span>
                <span>{formatBytes(memUsed)} / {container.memory}</span>
              </div>
              <UsageBar used={memPct} total={100} color={barColor(memPct)} />
            </div>
          )}
          {(diskUsed > 0 || diskLimit > 0) && (
            <div>
              <div className="mb-1 flex justify-between text-[10px] text-[var(--text-muted)]">
                <span>Disk</span>
                <span>{formatBytes(diskUsed)}{container.disk ? ` / ${container.disk}` : ' used'}</span>
              </div>
              <UsageBar used={diskPct || 100} total={100} color={barColor(diskPct)} />
            </div>
          )}
          {metrics && (
            <div className="flex flex-wrap gap-1">
              <span className="rounded bg-[var(--surface-2)] px-1.5 py-0.5 text-[10px] text-[var(--text-muted)]" title="Network I/O">
                Net: {formatBytes(metrics.networkRxBytes)}↓ {formatBytes(metrics.networkTxBytes)}↑
              </span>
              <span className="rounded bg-[var(--surface-2)] px-1.5 py-0.5 text-[10px] text-[var(--text-muted)]" title="Running processes">
                {metrics.processCount} procs
              </span>
            </div>
          )}
        </div>
      )}

      {/* Actions */}
      <div className="flex items-center justify-end gap-0.5 border-t border-[var(--border-subtle)] pt-2">
        {isRunning && container.accessType === 'ACCESS_TYPE_RDP' && (
          <IconBtn title="Remote Desktop" onClick={() => window.open('/guacamole/', '_blank')}>
            <Monitor size={14} />
          </IconBtn>
        )}
        {isRunning && container.accessType !== 'ACCESS_TYPE_RDP' && onTerminal && (
          <IconBtn title="Terminal" onClick={() => onTerminal(username)} className="hover:text-[var(--c-blue)]">
            <Terminal size={14} />
          </IconBtn>
        )}
        {onResize && (
          <IconBtn title="Resize Resources" onClick={() => onResize(username)}>
            <SlidersHorizontal size={14} />
          </IconBtn>
        )}
        {onEditFirewall && (
          <IconBtn title="Firewall" onClick={() => onEditFirewall(username)} className="hover:text-[var(--c-amber)]">
            <Shield size={14} />
          </IconBtn>
        )}
        {onToggleAutoSleep && (
          <IconBtn
            title={container.autoSleepEnabled ? `Auto-sleep · idle ${container.idleThresholdMinutes ?? 15}m` : 'Auto-sleep'}
            onClick={() => onToggleAutoSleep(username, {
              enabled: container.autoSleepEnabled ?? false,
              threshold: container.idleThresholdMinutes ?? 15,
            })}
            className={container.autoSleepEnabled ? 'text-indigo-400 hover:text-indigo-300' : 'hover:text-indigo-400'}
          >
            <Moon size={14} />
          </IconBtn>
        )}
        {onEditLabels && (
          <IconBtn title="Edit Labels" onClick={() => onEditLabels(username)}>
            <Tag size={14} />
          </IconBtn>
        )}
        {isRunning ? (
          <IconBtn title="Stop" onClick={() => onStop?.(username)} className="hover:text-[var(--c-amber)]">
            <Square size={14} />
          </IconBtn>
        ) : (
          <IconBtn title="Start" onClick={() => onStart?.(username)} className="hover:text-[var(--c-emerald)]">
            <Play size={14} />
          </IconBtn>
        )}
        <IconBtn title="Delete" onClick={() => onDelete(username)} className="hover:text-[var(--c-red)] hover:bg-red-500/10">
          <Trash2 size={14} />
        </IconBtn>
      </div>
    </div>
  );
}
