'use client';

import { useState, useEffect, useCallback } from 'react';
import { Box, Typography, CircularProgress, Alert, IconButton } from '@mui/material';
import RefreshIcon from '@mui/icons-material/Refresh';
import { Server } from '@/src/types/server';
import { getClient } from '@/src/lib/api/client';
// Backend health is now displayed natively in the Grafana dashboard via containarium_backend_healthy metric

interface MonitoringViewProps {
  server: Server;
}

export default function MonitoringView({ server }: MonitoringViewProps) {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [grafanaUrl, setGrafanaUrl] = useState<string>('');
  const [enabled, setEnabled] = useState(false);

  const fetchMonitoringInfo = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      const client = getClient(server);
      const info = await client.getMonitoringInfo();
      setEnabled(info.enabled);
      setGrafanaUrl(info.grafanaUrl);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to fetch monitoring info');
    } finally {
      setLoading(false);
    }
  }, [server]);

  useEffect(() => {
    fetchMonitoringInfo();
  }, [fetchMonitoringInfo]);

  if (loading) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '60vh' }}>
        <CircularProgress />
      </Box>
    );
  }

  if (error) {
    return (
      <Box sx={{ p: 3 }}>
        <Alert severity="error" action={
          <IconButton color="inherit" size="small" onClick={fetchMonitoringInfo}>
            <RefreshIcon />
          </IconButton>
        }>
          {error}
        </Alert>
      </Box>
    );
  }

  if (!enabled || !grafanaUrl) {
    return (
      <Box sx={{ p: 3, display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 2, mt: 8 }}>
        <Typography variant="h5" color="text.secondary">
          Monitoring Not Available
        </Typography>
        <Typography color="text.secondary" textAlign="center">
          Monitoring requires VictoriaMetrics and Grafana to be running.<br />
          Enable app hosting with <code>--app-hosting</code> to auto-provision the monitoring stack.
        </Typography>
      </Box>
    );
  }

  // Build the full Grafana base URL.
  // The API returns a relative path like "/grafana" — resolve it against the server endpoint.
  let grafanaBase = grafanaUrl;
  if (grafanaUrl.startsWith('/')) {
    const serverOrigin = new URL(server.endpoint.startsWith('http') ? server.endpoint : `https://${server.endpoint}`).origin;
    grafanaBase = `${serverOrigin}${grafanaUrl}`;
  }

  const iframeSrc = `${grafanaBase}/d/containarium-overview?orgId=1&kiosk&refresh=30s`;

  return (
    <Box sx={{ position: 'relative', height: 'calc(100vh - 150px)' }}>
      <iframe
        src={iframeSrc}
        style={{
          width: '100%',
          height: '100%',
          border: 'none',
          position: 'absolute',
          top: 0,
          left: 0,
        }}
        title="Containarium Monitoring"
      />
    </Box>
  );
}
