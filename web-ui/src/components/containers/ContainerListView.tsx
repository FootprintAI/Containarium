'use client';

import {
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  Chip,
  IconButton,
  Tooltip,
  Box,
  LinearProgress,
  Typography,
} from '@mui/material';
import DeleteIcon from '@mui/icons-material/Delete';
import PlayArrowIcon from '@mui/icons-material/PlayArrow';
import StopIcon from '@mui/icons-material/Stop';
import TerminalIcon from '@mui/icons-material/Terminal';
import SecurityIcon from '@mui/icons-material/Security';
import { Container, ContainerState, ContainerMetricsWithRate } from '@/src/types/container';

interface ContainerListViewProps {
  containers: Container[];
  metricsMap: Record<string, ContainerMetricsWithRate>;
  onDelete: (username: string) => void;
  onStart?: (username: string) => void;
  onStop?: (username: string) => void;
  onTerminal?: (username: string) => void;
  onEditFirewall?: (username: string) => void;
}

/**
 * Parse a size string like "4GB", "512MB", "50G" to bytes
 */
function parseSize(sizeStr: string): number {
  if (!sizeStr) return 0;
  const match = sizeStr.match(/^([\d.]+)\s*(B|KB|MB|GB|TB|K|M|G|T)?$/i);
  if (!match) return 0;
  const value = parseFloat(match[1]);
  const unit = (match[2] || 'B').toUpperCase();
  const multipliers: Record<string, number> = {
    'B': 1,
    'K': 1024,
    'KB': 1024,
    'M': 1024 * 1024,
    'MB': 1024 * 1024,
    'G': 1024 * 1024 * 1024,
    'GB': 1024 * 1024 * 1024,
    'T': 1024 * 1024 * 1024 * 1024,
    'TB': 1024 * 1024 * 1024 * 1024,
  };
  return value * (multipliers[unit] || 1);
}

/**
 * Format bytes to human readable string
 */
function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

function getStateColor(state: ContainerState): 'success' | 'error' | 'warning' | 'default' {
  switch (state) {
    case 'Running':
      return 'success';
    case 'Stopped':
      return 'error';
    case 'Frozen':
    case 'Creating':
      return 'warning';
    default:
      return 'default';
  }
}

function getUsageColor(percent: number): 'success' | 'warning' | 'error' {
  if (percent < 60) return 'success';
  if (percent < 80) return 'warning';
  return 'error';
}

interface UsageBarProps {
  used: number;
  total: number;
  label?: string;
}

function UsageBar({ used, total, label }: UsageBarProps) {
  const percent = total > 0 ? Math.min((used / total) * 100, 100) : 0;
  const color = getUsageColor(percent);

  return (
    <Tooltip title={`${formatBytes(used)} / ${formatBytes(total)} (${percent.toFixed(1)}%)`}>
      <Box sx={{ minWidth: 100 }}>
        <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mb: 0.25 }}>
          {label && `${label}: `}{formatBytes(used)} / {formatBytes(total)}
        </Typography>
        <LinearProgress
          variant="determinate"
          value={percent}
          color={color}
          sx={{ height: 4, borderRadius: 2 }}
        />
      </Box>
    </Tooltip>
  );
}

export default function ContainerListView({
  containers,
  metricsMap,
  onDelete,
  onStart,
  onStop,
  onTerminal,
  onEditFirewall,
}: ContainerListViewProps) {
  return (
    <TableContainer component={Paper} variant="outlined">
      <Table size="small">
        <TableHead>
          <TableRow sx={{ bgcolor: 'grey.50' }}>
            <TableCell><strong>Name</strong></TableCell>
            <TableCell><strong>State</strong></TableCell>
            <TableCell><strong>IP Address</strong></TableCell>
            <TableCell><strong>CPU</strong></TableCell>
            <TableCell><strong>Memory</strong></TableCell>
            <TableCell><strong>Disk</strong></TableCell>
            <TableCell align="right"><strong>Actions</strong></TableCell>
          </TableRow>
        </TableHead>
        <TableBody>
          {containers.map((container) => {
            const metrics = metricsMap[container.name];
            const isRunning = container.state === 'Running';
            const username = container.username || container.name;

            // Parse limits
            const memoryLimit = parseSize(container.memory);
            const diskLimit = parseSize(container.disk);
            const cpuCores = parseInt(container.cpu) || 0;

            // Get usage from metrics
            const memoryUsed = metrics?.memoryUsageBytes || 0;
            const diskUsed = metrics?.diskUsageBytes || 0;
            const cpuPercent = metrics?.cpuUsagePercent || 0;

            return (
              <TableRow
                key={container.name}
                sx={{ '&:hover': { bgcolor: 'action.hover' } }}
              >
                <TableCell>
                  <Box>
                    <Typography variant="body2" fontWeight="medium">
                      {username}
                    </Typography>
                    {container.image && (
                      <Typography variant="caption" color="text.secondary">
                        {container.image}
                      </Typography>
                    )}
                  </Box>
                </TableCell>

                <TableCell>
                  <Chip
                    label={container.state}
                    color={getStateColor(container.state)}
                    size="small"
                  />
                </TableCell>

                <TableCell>
                  <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>
                    {container.ipAddress || '-'}
                  </Typography>
                </TableCell>

                <TableCell>
                  {isRunning && cpuCores > 0 ? (
                    <Tooltip title={`${cpuPercent.toFixed(1)}% of ${cpuCores} cores`}>
                      <Typography variant="body2">
                        {cpuPercent.toFixed(1)}% / {cpuCores}c
                      </Typography>
                    </Tooltip>
                  ) : (
                    <Typography variant="body2" color="text.secondary">
                      {cpuCores > 0 ? `${cpuCores} cores` : '-'}
                    </Typography>
                  )}
                </TableCell>

                <TableCell>
                  {isRunning && memoryLimit > 0 ? (
                    <UsageBar used={memoryUsed} total={memoryLimit} />
                  ) : (
                    <Typography variant="body2" color="text.secondary">
                      {container.memory || '-'}
                    </Typography>
                  )}
                </TableCell>

                <TableCell>
                  {isRunning && diskLimit > 0 ? (
                    <UsageBar used={diskUsed} total={diskLimit} />
                  ) : isRunning && diskUsed > 0 ? (
                    <Typography variant="body2">
                      {formatBytes(diskUsed)} used
                    </Typography>
                  ) : (
                    <Typography variant="body2" color="text.secondary">
                      {container.disk || '-'}
                    </Typography>
                  )}
                </TableCell>

                <TableCell align="right">
                  <Box sx={{ display: 'flex', justifyContent: 'flex-end', gap: 0.5 }}>
                    {isRunning && onTerminal && (
                      <Tooltip title="Terminal">
                        <IconButton size="small" color="primary" onClick={() => onTerminal(username)}>
                          <TerminalIcon fontSize="small" />
                        </IconButton>
                      </Tooltip>
                    )}
                    {onEditFirewall && (
                      <Tooltip title="Firewall">
                        <IconButton size="small" color="warning" onClick={() => onEditFirewall(username)}>
                          <SecurityIcon fontSize="small" />
                        </IconButton>
                      </Tooltip>
                    )}
                    {isRunning ? (
                      <Tooltip title="Stop">
                        <IconButton size="small" onClick={() => onStop?.(username)}>
                          <StopIcon fontSize="small" />
                        </IconButton>
                      </Tooltip>
                    ) : (
                      <Tooltip title="Start">
                        <IconButton size="small" onClick={() => onStart?.(username)}>
                          <PlayArrowIcon fontSize="small" />
                        </IconButton>
                      </Tooltip>
                    )}
                    <Tooltip title="Delete">
                      <IconButton size="small" color="error" onClick={() => onDelete(username)}>
                        <DeleteIcon fontSize="small" />
                      </IconButton>
                    </Tooltip>
                  </Box>
                </TableCell>
              </TableRow>
            );
          })}
        </TableBody>
      </Table>
    </TableContainer>
  );
}
