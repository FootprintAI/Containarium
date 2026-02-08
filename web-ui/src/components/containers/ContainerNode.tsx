'use client';

import {
  Card,
  CardContent,
  Typography,
  Chip,
  Box,
  IconButton,
  Tooltip,
  LinearProgress,
} from '@mui/material';
import DeleteIcon from '@mui/icons-material/Delete';
import PlayArrowIcon from '@mui/icons-material/PlayArrow';
import StopIcon from '@mui/icons-material/Stop';
import TerminalIcon from '@mui/icons-material/Terminal';
import MemoryIcon from '@mui/icons-material/Memory';
import StorageIcon from '@mui/icons-material/Storage';
import DnsIcon from '@mui/icons-material/Dns';
import SecurityIcon from '@mui/icons-material/Security';
import LabelIcon from '@mui/icons-material/Label';
import { Container, ContainerState, ContainerMetricsWithRate } from '@/src/types/container';

interface ContainerNodeProps {
  container: Container;
  metrics?: ContainerMetricsWithRate;
  onDelete: (username: string) => void;
  onStart?: (username: string) => void;
  onStop?: (username: string) => void;
  onTerminal?: (username: string) => void;
  onEditFirewall?: (username: string) => void;
  onEditLabels?: (username: string) => void;
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

/**
 * Format CPU seconds to readable string
 */
function formatCpuTime(seconds: number): string {
  if (seconds < 60) return seconds.toFixed(1) + 's';
  if (seconds < 3600) return (seconds / 60).toFixed(1) + 'm';
  return (seconds / 3600).toFixed(1) + 'h';
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

export default function ContainerNode({ container, metrics, onDelete, onStart, onStop, onTerminal, onEditFirewall, onEditLabels }: ContainerNodeProps) {
  const isRunning = container.state === 'Running';

  // Calculate CPU, memory and disk utilization
  const cpuCores = parseInt(container.cpu) || 0;
  const cpuMaxPercent = cpuCores * 100; // 4 cores = 400% max
  const cpuUsagePercent = metrics?.cpuUsagePercent || 0;
  const cpuNormalized = cpuMaxPercent > 0 ? Math.min((cpuUsagePercent / cpuMaxPercent) * 100, 100) : 0;

  const memoryLimit = parseSize(container.memory);
  const diskLimit = parseSize(container.disk);
  const memoryUsed = metrics?.memoryUsageBytes || 0;
  const diskUsed = metrics?.diskUsageBytes || 0;
  const memoryPercent = memoryLimit > 0 ? Math.min((memoryUsed / memoryLimit) * 100, 100) : 0;
  const diskPercent = diskLimit > 0 ? Math.min((diskUsed / diskLimit) * 100, 100) : 0;

  return (
    <Card
      sx={{
        minWidth: 300,
        position: 'relative',
        '&:hover': {
          boxShadow: 4,
        },
      }}
    >
      <CardContent>
        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', mb: 1 }}>
          <Typography variant="h6" component="div" noWrap sx={{ maxWidth: '70%' }}>
            {container.username || container.name}
          </Typography>
          <Chip
            label={container.state}
            color={getStateColor(container.state)}
            size="small"
          />
        </Box>

        <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
          {container.image || 'ubuntu:24.04'}
        </Typography>

        {container.ipAddress && (
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
            <DnsIcon fontSize="small" color="action" />
            <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>
              {container.ipAddress}
            </Typography>
          </Box>
        )}

        {/* GPU chip if available */}
        {container.gpu && (
          <Box sx={{ mb: 2 }}>
            <Chip
              label={'GPU: ' + container.gpu}
              size="small"
              variant="outlined"
              color="secondary"
            />
          </Box>
        )}

        {/* CPU usage progress bar */}
        {isRunning && container.cpu && (
          <Box sx={{ mb: 1.5 }}>
            <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 0.5 }}>
              <Typography variant="caption" color="text.secondary">
                CPU
              </Typography>
              <Typography variant="caption" color="text.secondary">
                {cpuUsagePercent.toFixed(1)}% / {cpuCores} cores
              </Typography>
            </Box>
            <LinearProgress
              variant="determinate"
              value={cpuNormalized}
              sx={{
                height: 8,
                borderRadius: 4,
                bgcolor: 'grey.200',
                '& .MuiLinearProgress-bar': {
                  bgcolor: cpuNormalized > 80 ? 'error.main' : cpuNormalized > 60 ? 'warning.main' : 'success.main',
                  borderRadius: 4,
                },
              }}
            />
          </Box>
        )}

        {/* Memory usage progress bar */}
        {isRunning && container.memory && (
          <Box sx={{ mb: 1.5 }}>
            <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 0.5 }}>
              <Typography variant="caption" color="text.secondary">
                Memory
              </Typography>
              <Typography variant="caption" color="text.secondary">
                {formatBytes(memoryUsed)} / {container.memory}
              </Typography>
            </Box>
            <LinearProgress
              variant="determinate"
              value={memoryPercent}
              sx={{
                height: 8,
                borderRadius: 4,
                bgcolor: 'grey.200',
                '& .MuiLinearProgress-bar': {
                  bgcolor: memoryPercent > 80 ? 'error.main' : memoryPercent > 60 ? 'warning.main' : 'primary.main',
                  borderRadius: 4,
                },
              }}
            />
          </Box>
        )}

        {/* Disk usage progress bar */}
        {isRunning && (diskUsed > 0 || container.disk) && (
          <Box sx={{ mb: 1.5 }}>
            <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 0.5 }}>
              <Typography variant="caption" color="text.secondary">
                Disk
              </Typography>
              <Typography variant="caption" color="text.secondary">
                {formatBytes(diskUsed)}{container.disk ? ` / ${container.disk}` : ' used'}
              </Typography>
            </Box>
            {container.disk ? (
              <LinearProgress
                variant="determinate"
                value={diskPercent}
                sx={{
                  height: 8,
                  borderRadius: 4,
                  bgcolor: 'grey.200',
                  '& .MuiLinearProgress-bar': {
                    bgcolor: diskPercent > 80 ? 'error.main' : diskPercent > 60 ? 'warning.main' : 'info.main',
                    borderRadius: 4,
                  },
                }}
              />
            ) : (
              <LinearProgress
                variant="determinate"
                value={100}
                sx={{
                  height: 8,
                  borderRadius: 4,
                  bgcolor: 'grey.200',
                  '& .MuiLinearProgress-bar': {
                    bgcolor: 'info.main',
                    borderRadius: 4,
                  },
                }}
              />
            )}
          </Box>
        )}

        {/* Other metrics (simple text) */}
        {isRunning && metrics && (
          <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1, mb: 1 }}>
            <Tooltip title="Network I/O (received / sent)">
              <Chip
                label={'Net: ' + formatBytes(metrics.networkRxBytes) + ' / ' + formatBytes(metrics.networkTxBytes)}
                size="small"
                variant="outlined"
                sx={{ fontSize: '0.7rem' }}
              />
            </Tooltip>
            <Tooltip title="Running processes">
              <Chip
                label={'Proc: ' + metrics.processCount}
                size="small"
                variant="outlined"
                sx={{ fontSize: '0.7rem' }}
              />
            </Tooltip>
          </Box>
        )}

        <Box sx={{ display: 'flex', justifyContent: 'flex-end', gap: 1 }}>
          {isRunning && onTerminal && (
            <Tooltip title="Open Terminal">
              <IconButton
                size="small"
                color="primary"
                onClick={() => onTerminal(container.username || container.name)}
              >
                <TerminalIcon />
              </IconButton>
            </Tooltip>
          )}
          {onEditFirewall && (
            <Tooltip title="Firewall Settings">
              <IconButton
                size="small"
                color="warning"
                onClick={() => onEditFirewall(container.username || container.name)}
              >
                <SecurityIcon />
              </IconButton>
            </Tooltip>
          )}
          {onEditLabels && (
            <Tooltip title="Edit Labels">
              <IconButton
                size="small"
                color="info"
                onClick={() => onEditLabels(container.username || container.name)}
              >
                <LabelIcon />
              </IconButton>
            </Tooltip>
          )}
          {isRunning ? (
            <Tooltip title="Stop">
              <IconButton size="small" onClick={() => onStop?.(container.username || container.name)}>
                <StopIcon />
              </IconButton>
            </Tooltip>
          ) : (
            <Tooltip title="Start">
              <IconButton size="small" onClick={() => onStart?.(container.username || container.name)}>
                <PlayArrowIcon />
              </IconButton>
            </Tooltip>
          )}
          <Tooltip title="Delete">
            <IconButton
              size="small"
              color="error"
              onClick={() => onDelete(container.username || container.name)}
            >
              <DeleteIcon />
            </IconButton>
          </Tooltip>
        </Box>
      </CardContent>
    </Card>
  );
}
