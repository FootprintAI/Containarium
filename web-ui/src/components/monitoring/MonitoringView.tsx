'use client';

import { useState, useEffect, useCallback } from 'react';
import { Loader2, RefreshCw } from 'lucide-react';
import { Server } from '@/src/types/server';
import { getClient } from '@/src/lib/api/client';

export default function MonitoringView({ server }: { server: Server }) {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [grafanaUrl, setGrafanaUrl] = useState('');
  const [enabled, setEnabled] = useState(false);

  const fetchInfo = useCallback(async () => {
    try {
      setLoading(true); setError(null);
      const client = getClient(server);
      const info = await client.getMonitoringInfo();
      // Mint the same-origin session cookie BEFORE the iframe paints,
      // so the iframe's request to /grafana/* carries auth. Iframes
      // can't attach an Authorization header from localStorage, so
      // without this the embedded Grafana 401s. Issue #338.
      if (info.enabled && info.grafanaUrl) {
        try {
          await client.setSessionCookie();
        } catch (e) {
          // Older daemons (pre-#338) don't have this endpoint. Don't
          // block the monitoring page render — the iframe will surface
          // its own 401, which is no worse than the pre-fix behavior.
          console.warn('Failed to set session cookie; embedded Grafana may 401', e);
        }
      }
      setEnabled(info.enabled);
      setGrafanaUrl(info.grafanaUrl);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to fetch monitoring info');
    } finally {
      setLoading(false);
    }
  }, [server]);

  useEffect(() => { fetchInfo(); }, [fetchInfo]);

  if (loading) {
    return (
      <div className="flex h-60 items-center justify-center">
        <Loader2 size={24} className="animate-spin text-[var(--text-secondary)]" />
      </div>
    );
  }

  if (error) {
    return (
      <div className="p-6">
        <div className="flex items-center gap-3 rounded-lg border border-red-500/30 bg-red-500/10 p-4 text-sm text-[var(--c-red)]">
          <span className="flex-1">{error}</span>
          <button onClick={fetchInfo} className="rounded p-1 hover:bg-red-500/20 transition-colors">
            <RefreshCw size={14} />
          </button>
        </div>
      </div>
    );
  }

  if (!enabled || !grafanaUrl) {
    return (
      <div className="flex flex-col items-center justify-center gap-3 py-24">
        <p className="text-sm font-medium text-[var(--text-secondary)]">Monitoring Not Available</p>
        <p className="text-center text-xs text-[var(--text-muted)]">
          Monitoring requires VictoriaMetrics and Grafana to be running.<br />
          Enable app hosting with <code className="rounded bg-[var(--surface-2)] px-1">--app-hosting</code> to auto-provision the monitoring stack.
        </p>
      </div>
    );
  }

  let grafanaBase = grafanaUrl;
  if (grafanaUrl.startsWith('/')) {
    const origin = new URL(server.endpoint.startsWith('http') ? server.endpoint : `https://${server.endpoint}`).origin;
    grafanaBase = `${origin}${grafanaUrl}`;
  }

  return (
    <div className="relative h-[calc(100vh-150px)]">
      <iframe
        src={`${grafanaBase}/d/containarium-overview?orgId=1&kiosk&refresh=30s`}
        className="absolute inset-0 h-full w-full border-0"
        title="Containarium Monitoring"
      />
    </div>
  );
}
