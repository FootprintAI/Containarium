'use client';

import {
  Trash2, Play, Square, Terminal, Monitor, Shield,
  Tag, SlidersHorizontal, Users, Moon,
} from 'lucide-react';
import { Container, ContainerState, ContainerMetricsWithRate } from '@/src/types/container';

interface ContainerListViewProps {
  containers: Container[];
  metricsMap: Record<string, ContainerMetricsWithRate>;
  onDelete: (username: string) => void;
  onStart?: (username: string) => void;
  onStop?: (username: string) => void;
  onTerminal?: (username: string) => void;
  onEditFirewall?: (username: string) => void;
  onEditLabels?: (username: string, labels: Record<string, string>) => void;
  onResize?: (username: string, currentResources: { cpu: string; memory: string; disk: string }) => void;
  onManageCollaborators?: (username: string) => void;
  onToggleAutoSleep?: (username: string, current: { enabled: boolean; threshold: number }) => void;
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

function MiniBar({ pct }: { pct: number }) {
  const color = pct > 80 ? 'bg-red-500' : pct > 60 ? 'bg-amber-500' : 'bg-emerald-500';
  return (
    <div className="h-1 w-20 rounded-full bg-zinc-800">
      <div className={`h-full rounded-full ${color}`} style={{ width: `${Math.min(pct, 100)}%` }} />
    </div>
  );
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

export default function ContainerListView({
  containers, metricsMap, onDelete, onStart, onStop, onTerminal,
  onEditFirewall, onEditLabels, onResize, onManageCollaborators, onToggleAutoSleep,
}: ContainerListViewProps) {
  return (
    <div className="overflow-x-auto rounded-xl border border-[var(--border-subtle)]">
      <table className="w-full text-xs">
        <thead>
          <tr className="border-b border-[var(--border-subtle)] bg-[var(--surface)]">
            {['Name', 'State', 'IP Address', 'CPU', 'Memory', 'Disk', 'Node', 'Labels', ''].map((h) => (
              <th key={h} className="px-3 py-2.5 text-left font-medium text-[var(--text-secondary)] whitespace-nowrap last:text-right">
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {containers.map((c) => {
            const metrics = metricsMap[c.name];
            const isRunning = c.state === 'Running';
            const username = c.username || c.name;

            const memLimit = parseSize(c.memory);
            const diskLimit = parseSize(c.disk);
            const cpuCores = parseInt(c.cpu) || 0;
            const memUsed = metrics?.memoryUsageBytes || 0;
            const diskUsed = metrics?.diskUsageBytes || 0;
            const cpuPct = metrics?.cpuUsagePercent || 0;
            const memPct = memLimit > 0 ? (memUsed / memLimit) * 100 : 0;
            const diskPct = diskLimit > 0 ? (diskUsed / diskLimit) * 100 : 0;

            return (
              <tr key={c.name} className="border-b border-[var(--border-subtle)] transition-colors hover:bg-[var(--surface)]">
                {/* Name */}
                <td className="px-3 py-2.5">
                  <p className="font-medium text-[var(--text)]">{username}</p>
                  {c.image && <p className="text-[var(--text-muted)]">{c.image}</p>}
                </td>

                {/* State */}
                <td className="px-3 py-2.5">
                  {c.state === 'Stopped' && c.autoSleepEnabled ? (
                    <span className="inline-flex items-center gap-1 rounded-full border border-indigo-500/30 bg-indigo-500/15 px-2 py-0.5 text-[10px] font-medium text-indigo-400">
                      <Moon size={10} />
                      Sleeping
                    </span>
                  ) : (
                    <span className={`rounded-full border px-2 py-0.5 text-[10px] font-medium ${stateBadge(c.state)}`}>
                      {c.state}
                    </span>
                  )}
                </td>

                {/* IP */}
                <td className="px-3 py-2.5 font-mono text-[var(--text-secondary)]">
                  {c.ipAddress || <span className="text-[var(--text-muted)]">—</span>}
                </td>

                {/* CPU */}
                <td className="px-3 py-2.5">
                  {isRunning && cpuCores > 0 ? (
                    <div title={`${cpuPct.toFixed(1)}% of ${cpuCores} cores`}>
                      <p className="text-[var(--text)]">{cpuPct.toFixed(1)}% / {cpuCores}c</p>
                      <MiniBar pct={cpuPct / cpuCores} />
                    </div>
                  ) : (
                    <span className="text-[var(--text-muted)]">{cpuCores > 0 ? `${cpuCores}c` : '—'}</span>
                  )}
                </td>

                {/* Memory */}
                <td className="px-3 py-2.5">
                  {isRunning && memLimit > 0 ? (
                    <div title={`${formatBytes(memUsed)} / ${formatBytes(memLimit)}`}>
                      <p className="text-[var(--text)]">{formatBytes(memUsed)} / {c.memory}</p>
                      <MiniBar pct={memPct} />
                    </div>
                  ) : (
                    <span className="text-[var(--text-muted)]">{c.memory || '—'}</span>
                  )}
                </td>

                {/* Disk */}
                <td className="px-3 py-2.5">
                  {isRunning && diskLimit > 0 ? (
                    <div title={`${formatBytes(diskUsed)} / ${formatBytes(diskLimit)}`}>
                      <p className="text-[var(--text)]">{formatBytes(diskUsed)} / {c.disk}</p>
                      <MiniBar pct={diskPct} />
                    </div>
                  ) : isRunning && diskUsed > 0 ? (
                    <span className="text-[var(--text)]">{formatBytes(diskUsed)} used</span>
                  ) : (
                    <span className="text-[var(--text-muted)]">{c.disk || '—'}</span>
                  )}
                </td>

                {/* Node */}
                <td className="px-3 py-2.5">
                  {c.backendId ? (
                    <span className={`rounded border px-1.5 py-0.5 text-[10px] ${c.backendId.startsWith('tunnel-') ? 'border-indigo-500/30 bg-indigo-500/10 text-indigo-400' : 'border-blue-500/30 bg-blue-500/10 text-[var(--c-blue)]'}`}>
                      {c.backendId}
                    </span>
                  ) : <span className="text-[var(--text-muted)]">—</span>}
                </td>

                {/* Labels */}
                <td className="px-3 py-2.5">
                  <div className="flex flex-wrap items-center gap-1 max-w-[180px]">
                    {c.labels && Object.keys(c.labels).length > 0 ? (
                      Object.entries(c.labels).slice(0, 3).map(([k, v]) => (
                        <span key={k} title={`${k}=${v}`} className="max-w-[130px] truncate rounded bg-[var(--surface-2)] px-1.5 py-0.5 text-[10px] text-[var(--text-secondary)]">
                          {k}={v}
                        </span>
                      ))
                    ) : <span className="text-[var(--text-muted)]">—</span>}
                    {onEditLabels && (
                      <IconBtn title="Edit Labels" onClick={() => onEditLabels(username, c.labels || {})}>
                        <Tag size={11} />
                      </IconBtn>
                    )}
                  </div>
                </td>

                {/* Actions */}
                <td className="px-3 py-2.5">
                  <div className="flex items-center justify-end gap-0.5">
                    {isRunning && c.accessType === 'ACCESS_TYPE_RDP' && (
                      <IconBtn title="Remote Desktop" onClick={() => window.open('/guacamole/', '_blank')}>
                        <Monitor size={13} />
                      </IconBtn>
                    )}
                    {isRunning && c.accessType !== 'ACCESS_TYPE_RDP' && onTerminal && (
                      <IconBtn title="Terminal" onClick={() => onTerminal(username)} className="hover:text-[var(--c-blue)]">
                        <Terminal size={13} />
                      </IconBtn>
                    )}
                    {onResize && (
                      <IconBtn title="Resize" onClick={() => onResize(username, { cpu: c.cpu, memory: c.memory, disk: c.disk })}>
                        <SlidersHorizontal size={13} />
                      </IconBtn>
                    )}
                    {isRunning && onManageCollaborators && (
                      <IconBtn title="Collaborators" onClick={() => onManageCollaborators(username)}>
                        <Users size={13} />
                      </IconBtn>
                    )}
                    {onEditFirewall && (
                      <IconBtn title="Firewall" onClick={() => onEditFirewall(username)} className="hover:text-[var(--c-amber)]">
                        <Shield size={13} />
                      </IconBtn>
                    )}
                    {onToggleAutoSleep && (
                      <IconBtn
                        title={c.autoSleepEnabled ? `Auto-sleep · idle ${c.idleThresholdMinutes ?? 15}m` : 'Auto-sleep'}
                        onClick={() => onToggleAutoSleep(username, {
                          enabled: c.autoSleepEnabled ?? false,
                          threshold: c.idleThresholdMinutes ?? 15,
                        })}
                        className={c.autoSleepEnabled ? 'text-indigo-400 hover:text-indigo-300' : 'hover:text-indigo-400'}
                      >
                        <Moon size={13} />
                      </IconBtn>
                    )}
                    {isRunning ? (
                      <IconBtn title="Stop" onClick={() => onStop?.(username)} className="hover:text-[var(--c-amber)]">
                        <Square size={13} />
                      </IconBtn>
                    ) : (
                      <IconBtn title="Start" onClick={() => onStart?.(username)} className="hover:text-[var(--c-emerald)]">
                        <Play size={13} />
                      </IconBtn>
                    )}
                    <IconBtn title="Delete" onClick={() => onDelete(username)} className="hover:text-[var(--c-red)] hover:bg-red-500/10">
                      <Trash2 size={13} />
                    </IconBtn>
                  </div>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
