'use client';

import { useState, useMemo, useEffect, useRef, useCallback } from 'react';
import {
  Box,
  Typography,
  CircularProgress,
  Alert,
  IconButton,
  Paper,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Chip,
  Button,
  TextField,
  Stack,
  Collapse,
  LinearProgress,
  Tabs,
  Tab,
} from '@mui/material';
import RefreshIcon from '@mui/icons-material/Refresh';
import DownloadIcon from '@mui/icons-material/Download';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import ExpandLessIcon from '@mui/icons-material/ExpandLess';
import ShieldIcon from '@mui/icons-material/Shield';
import BugReportIcon from '@mui/icons-material/BugReport';
import PlayArrowIcon from '@mui/icons-material/PlayArrow';
import ScannerIcon from '@mui/icons-material/Scanner';
import HourglassEmptyIcon from '@mui/icons-material/HourglassEmpty';
import CheckCircleOutlineIcon from '@mui/icons-material/CheckCircleOutline';
import ErrorOutlineIcon from '@mui/icons-material/ErrorOutline';
import Tooltip from '@mui/material/Tooltip';
import Snackbar from '@mui/material/Snackbar';
import { Server } from '@/src/types/server';
import { ClamavContainerSummary, ClamavReport, ScanStatusResponse } from '@/src/types/security';
import { useSecurity } from '@/src/lib/hooks/useSecurity';
import { getClient } from '@/src/lib/api/client';
import PentestView from './PentestView';

interface SecurityViewProps {
  server: Server;
}

function formatDate(iso: string): string {
  if (!iso) return 'Never';
  try {
    return new Date(iso).toLocaleString();
  } catch {
    return iso;
  }
}

function StatusChip({ status }: { status: string }) {
  switch (status) {
    case 'clean':
      return <Chip label="Clean" color="success" size="small" />;
    case 'infected':
      return <Chip label="Infected" color="error" size="small" />;
    case 'never':
      return <Chip label="Never Scanned" size="small" sx={{ bgcolor: 'grey.300' }} />;
    default:
      return <Chip label={status} size="small" />;
  }
}

function SummaryCard({ title, value, color }: { title: string; value: number; color: string }) {
  return (
    <Paper sx={{ p: 2, textAlign: 'center', minWidth: 140 }}>
      <Typography variant="h4" sx={{ color, fontWeight: 'bold' }}>
        {value}
      </Typography>
      <Typography variant="body2" color="text.secondary">
        {title}
      </Typography>
    </Paper>
  );
}

function ContainerScanAction({ containerName, scanStatus, onScan }: {
  containerName: string;
  scanStatus: ScanStatusResponse | null;
  onScan: (name: string) => void;
}) {
  // Find the most recent job for this container
  const job = scanStatus?.jobs?.find(j => j.containerName === containerName && (j.status === 'pending' || j.status === 'running'));

  if (job?.status === 'pending') {
    return (
      <Tooltip title="Queued — waiting for available worker">
        <HourglassEmptyIcon fontSize="small" color="action" />
      </Tooltip>
    );
  }
  if (job?.status === 'running') {
    return (
      <Tooltip title="Scanning...">
        <CircularProgress size={18} />
      </Tooltip>
    );
  }

  // Check for recently completed/failed jobs (within last poll cycle)
  const recentJob = scanStatus?.jobs?.find(j => j.containerName === containerName);
  if (recentJob?.status === 'failed') {
    return (
      <Tooltip title={`Failed: ${recentJob.errorMessage || 'unknown error'}`}>
        <IconButton
          size="small"
          onClick={(e) => { e.stopPropagation(); onScan(containerName); }}
        >
          <ErrorOutlineIcon fontSize="small" color="error" />
        </IconButton>
      </Tooltip>
    );
  }
  if (recentJob?.status === 'completed') {
    return (
      <Tooltip title="Scan completed — click to re-scan">
        <IconButton
          size="small"
          onClick={(e) => { e.stopPropagation(); onScan(containerName); }}
        >
          <CheckCircleOutlineIcon fontSize="small" color="success" />
        </IconButton>
      </Tooltip>
    );
  }

  // Default: idle — show scanner icon
  return (
    <Tooltip title="Trigger scan">
      <IconButton
        size="small"
        onClick={(e) => { e.stopPropagation(); onScan(containerName); }}
      >
        <ScannerIcon fontSize="small" />
      </IconButton>
    </Tooltip>
  );
}

function ContainerRow({ container, server, onScan, scanStatus }: { container: ClamavContainerSummary; server: Server; onScan: (name: string) => void; scanStatus: ScanStatusResponse | null }) {
  const [expanded, setExpanded] = useState(false);
  const [history, setHistory] = useState<ClamavReport[]>([]);
  const [historyLoading, setHistoryLoading] = useState(false);

  const loadHistory = async () => {
    if (history.length > 0) {
      setExpanded(!expanded);
      return;
    }
    setHistoryLoading(true);
    try {
      const client = getClient(server);
      const result = await client.listClamavReports({
        containerName: container.containerName,
        limit: 20,
      });
      setHistory(result.reports);
      setExpanded(true);
    } catch (err) {
      console.error('Failed to load history:', err);
    } finally {
      setHistoryLoading(false);
    }
  };

  return (
    <>
      <TableRow
        hover
        sx={{ cursor: 'pointer' }}
        onClick={loadHistory}
      >
        <TableCell>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            {expanded ? <ExpandLessIcon fontSize="small" /> : <ExpandMoreIcon fontSize="small" />}
            {container.containerName}
          </Box>
        </TableCell>
        <TableCell>{container.username}</TableCell>
        <TableCell>{formatDate(container.lastScanAt)}</TableCell>
        <TableCell><StatusChip status={container.lastStatus} /></TableCell>
        <TableCell align="right">{container.lastFindingsCount}</TableCell>
        <TableCell align="right">{container.totalScans}</TableCell>
        <TableCell align="right">
          <ContainerScanAction
            containerName={container.containerName}
            scanStatus={scanStatus}
            onScan={onScan}
          />
        </TableCell>
      </TableRow>
      <TableRow>
        <TableCell colSpan={7} sx={{ py: 0, borderBottom: expanded ? undefined : 'none' }}>
          <Collapse in={expanded} timeout="auto" unmountOnExit>
            <Box sx={{ py: 1, pl: 4 }}>
              {historyLoading ? (
                <CircularProgress size={20} />
              ) : history.length === 0 ? (
                <Typography variant="body2" color="text.secondary">No scan history</Typography>
              ) : (
                <Table size="small">
                  <TableHead>
                    <TableRow>
                      <TableCell>Scanned At</TableCell>
                      <TableCell>Status</TableCell>
                      <TableCell>Findings</TableCell>
                      <TableCell>Duration</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {history.map((report) => (
                      <TableRow key={report.id}>
                        <TableCell>{formatDate(report.scannedAt)}</TableCell>
                        <TableCell><StatusChip status={report.status} /></TableCell>
                        <TableCell>
                          {report.findingsCount > 0 ? (
                            <Typography variant="body2" sx={{ whiteSpace: 'pre-wrap', fontFamily: 'monospace', fontSize: '0.75rem' }}>
                              {report.findings}
                            </Typography>
                          ) : (
                            <Typography variant="body2" color="text.secondary">None</Typography>
                          )}
                        </TableCell>
                        <TableCell>{report.scanDuration}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
            </Box>
          </Collapse>
        </TableCell>
      </TableRow>
    </>
  );
}

export default function SecurityView({ server }: SecurityViewProps) {
  const [securityTab, setSecurityTab] = useState(0);

  return (
    <Box sx={{ p: 3 }}>
      {/* Sub-tabs */}
      <Tabs
        value={securityTab}
        onChange={(_, v) => setSecurityTab(v)}
        sx={{ mb: 3, borderBottom: 1, borderColor: 'divider' }}
      >
        <Tab icon={<ShieldIcon />} iconPosition="start" label="Malware Scan" />
        <Tab icon={<BugReportIcon />} iconPosition="start" label="Pentest" />
      </Tabs>

      {securityTab === 0 && <ClamavView server={server} />}
      {securityTab === 1 && <PentestView server={server} />}
    </Box>
  );
}

function ClamavView({ server }: SecurityViewProps) {
  const { summary, isLoading, error, refresh } = useSecurity(server);

  // Scan state
  const [scanningAll, setScanningAll] = useState(false);
  const [scanningContainer, setScanningContainer] = useState<string | null>(null);
  const [snackMessage, setSnackMessage] = useState<string | null>(null);
  const [scanStatus, setScanStatus] = useState<ScanStatusResponse | null>(null);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const stopPolling = useCallback(() => {
    if (pollRef.current) {
      clearInterval(pollRef.current);
      pollRef.current = null;
    }
  }, []);

  const startPolling = useCallback(() => {
    stopPolling();
    const client = getClient(server);
    const poll = async () => {
      try {
        const status = await client.getScanStatus();
        setScanStatus(status);
        // Stop polling when no active jobs remain
        if (status.pendingCount === 0 && status.runningCount === 0) {
          stopPolling();
          setScanningAll(false);
          setScanningContainer(null);
          refresh();
        }
      } catch {
        // Ignore polling errors
      }
    };
    poll(); // Immediate first poll
    pollRef.current = setInterval(poll, 5000);
  }, [server, stopPolling, refresh]);

  // Cleanup polling on unmount
  useEffect(() => {
    return () => stopPolling();
  }, [stopPolling]);

  const handleScanAll = async () => {
    setScanningAll(true);
    try {
      const client = getClient(server);
      const result = await client.triggerClamavScan();
      setSnackMessage(result.message || `${result.scannedCount} scan jobs queued`);
      startPolling();
    } catch (err) {
      setSnackMessage(err instanceof Error ? err.message : 'Scan failed');
      setScanningAll(false);
    }
  };

  const handleScanContainer = async (containerName: string) => {
    setScanningContainer(containerName);
    try {
      const client = getClient(server);
      const result = await client.triggerClamavScan(containerName);
      setSnackMessage(result.message || `Scan queued for ${containerName}`);
      startPolling();
    } catch (err) {
      setSnackMessage(err instanceof Error ? err.message : 'Scan failed');
      setScanningContainer(null);
    }
  };

  const isScanning = scanningAll || !!scanningContainer;

  // Date range for CSV export
  const today = new Date().toISOString().slice(0, 10);
  const weekAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString().slice(0, 10);
  const [exportFrom, setExportFrom] = useState(weekAgo);
  const [exportTo, setExportTo] = useState(today);

  // Sort: infected first, then never, then clean
  const sortedContainers = useMemo(() => {
    if (!summary?.containers) return [];
    return [...summary.containers].sort((a, b) => {
      const order: Record<string, number> = { infected: 0, never: 1, clean: 2 };
      return (order[a.lastStatus] ?? 3) - (order[b.lastStatus] ?? 3);
    });
  }, [summary?.containers]);

  const handleDownload = () => {
    const client = getClient(server);
    const url = client.getClamavReportExportUrl(exportFrom, exportTo);
    window.open(url, '_blank');
  };

  if (isLoading) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '40vh' }}>
        <CircularProgress />
      </Box>
    );
  }

  if (error) {
    return (
      <Alert severity="error" action={
        <IconButton color="inherit" size="small" onClick={refresh}>
          <RefreshIcon />
        </IconButton>
      }>
        {error instanceof Error ? error.message : 'Failed to fetch security data'}
      </Alert>
    );
  }

  return (
    <Box>
      {/* Header */}
      <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 3 }}>
        <Typography variant="h6">ClamAV Malware Scanning</Typography>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <Button
            variant="contained"
            size="small"
            startIcon={scanningAll ? <CircularProgress size={16} color="inherit" /> : <PlayArrowIcon />}
            onClick={handleScanAll}
            disabled={scanningAll || !!scanningContainer}
          >
            Scan All
          </Button>
          <IconButton onClick={refresh} size="small">
            <RefreshIcon />
          </IconButton>
        </Box>
      </Box>

      {/* Summary Cards */}
      <Stack direction="row" spacing={2} sx={{ mb: 3, flexWrap: 'wrap' }}>
        <SummaryCard title="Total Containers" value={summary?.totalContainers || 0} color="text.primary" />
        <SummaryCard title="Clean" value={summary?.cleanContainers || 0} color="success.main" />
        <SummaryCard title="Infected" value={summary?.infectedContainers || 0} color="error.main" />
        <SummaryCard title="Never Scanned" value={summary?.neverScannedContainers || 0} color="text.secondary" />
      </Stack>

      {/* Scan Progress */}
      {isScanning && scanStatus && (scanStatus.pendingCount > 0 || scanStatus.runningCount > 0) && (
        <Paper sx={{ p: 2, mb: 3 }}>
          <Typography variant="subtitle2" gutterBottom>Scan Progress</Typography>
          <Box sx={{ mb: 1 }}>
            <LinearProgress
              variant="determinate"
              value={
                scanStatus.completedCount + scanStatus.failedCount + scanStatus.runningCount + scanStatus.pendingCount > 0
                  ? ((scanStatus.completedCount + scanStatus.failedCount) /
                      (scanStatus.completedCount + scanStatus.failedCount + scanStatus.runningCount + scanStatus.pendingCount)) * 100
                  : 0
              }
            />
          </Box>
          <Stack direction="row" spacing={2}>
            <Typography variant="body2" color="text.secondary">
              Pending: {scanStatus.pendingCount}
            </Typography>
            <Typography variant="body2" color="info.main">
              Running: {scanStatus.runningCount}
            </Typography>
            <Typography variant="body2" color="success.main">
              Completed: {scanStatus.completedCount}
            </Typography>
            {scanStatus.failedCount > 0 && (
              <Typography variant="body2" color="error.main">
                Failed: {scanStatus.failedCount}
              </Typography>
            )}
          </Stack>
        </Paper>
      )}

      {/* CSV Download Section */}
      <Paper sx={{ p: 2, mb: 3 }}>
        <Typography variant="subtitle2" gutterBottom>Download Scan Reports</Typography>
        <Stack direction="row" spacing={2} alignItems="center">
          <TextField
            type="date"
            label="Start Date"
            value={exportFrom}
            onChange={(e) => setExportFrom(e.target.value)}
            size="small"
            InputLabelProps={{ shrink: true }}
          />
          <TextField
            type="date"
            label="End Date"
            value={exportTo}
            onChange={(e) => setExportTo(e.target.value)}
            size="small"
            InputLabelProps={{ shrink: true }}
          />
          <Button
            variant="contained"
            startIcon={<DownloadIcon />}
            onClick={handleDownload}
            size="small"
          >
            Download CSV
          </Button>
        </Stack>
      </Paper>

      {/* Container Table */}
      <TableContainer component={Paper}>
        <Table>
          <TableHead>
            <TableRow>
              <TableCell>Container</TableCell>
              <TableCell>Username</TableCell>
              <TableCell>Last Scan</TableCell>
              <TableCell>Status</TableCell>
              <TableCell align="right">Findings</TableCell>
              <TableCell align="right">Total Scans</TableCell>
              <TableCell align="right">Actions</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {sortedContainers.length === 0 ? (
              <TableRow>
                <TableCell colSpan={7} align="center">
                  <Typography color="text.secondary" sx={{ py: 4 }}>
                    No containers found. The security scanner runs every 24 hours.
                  </Typography>
                </TableCell>
              </TableRow>
            ) : (
              sortedContainers.map((container) => (
                <ContainerRow
                  key={container.containerName}
                  container={container}
                  server={server}
                  onScan={handleScanContainer}
                  scanStatus={scanStatus}
                />
              ))
            )}
          </TableBody>
        </Table>
      </TableContainer>

      {/* Last Collection Time */}
      {summary?.lastCollectionAt && (
        <Typography variant="caption" color="text.secondary" sx={{ mt: 1, display: 'block' }}>
          Summary generated at: {formatDate(summary.lastCollectionAt)}
        </Typography>
      )}

      <Snackbar
        open={!!snackMessage}
        autoHideDuration={5000}
        onClose={() => setSnackMessage(null)}
        message={snackMessage}
      />
    </Box>
  );
}
