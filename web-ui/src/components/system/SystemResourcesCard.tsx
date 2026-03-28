'use client';

import { useState, useEffect } from 'react';
import { Box, Card, CardContent, Typography, LinearProgress, Grid, Tooltip, ToggleButtonGroup, ToggleButton } from '@mui/material';
import MemoryIcon from '@mui/icons-material/Memory';
import StorageIcon from '@mui/icons-material/Storage';
import ComputerIcon from '@mui/icons-material/Computer';
import GpuIcon from '@mui/icons-material/DeveloperBoard';
import { SystemInfo, BackendInfo, gpuVendorDisplayName, gpuModelDisplayName } from '@/src/types/container';

interface SystemResourcesCardProps {
  systemInfo: SystemInfo | null;
  backends?: BackendInfo[];
  onSelectBackend?: (backendId: string) => Promise<SystemInfo | null>;
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
 * Get color based on usage percentage
 */
function getUsageColor(percent: number): 'success' | 'warning' | 'error' {
  if (percent < 60) return 'success';
  if (percent < 80) return 'warning';
  return 'error';
}

export default function SystemResourcesCard({ systemInfo, backends, onSelectBackend }: SystemResourcesCardProps) {
  const [selectedBackend, setSelectedBackend] = useState<string>('');
  const [backendSystemInfo, setBackendSystemInfo] = useState<SystemInfo | null>(null);
  const [loading, setLoading] = useState(false);

  const activeInfo = selectedBackend && backendSystemInfo ? backendSystemInfo : systemInfo;

  const handleBackendChange = async (_: React.MouseEvent<HTMLElement>, value: string | null) => {
    const newValue = value || '';
    setSelectedBackend(newValue);
    if (!newValue || !onSelectBackend) {
      setBackendSystemInfo(null);
      return;
    }
    setLoading(true);
    try {
      const info = await onSelectBackend(newValue);
      setBackendSystemInfo(info);
    } catch {
      setBackendSystemInfo(null);
    } finally {
      setLoading(false);
    }
  };

  // Auto-refresh selected backend info
  useEffect(() => {
    if (!selectedBackend || !onSelectBackend) return;
    const interval = setInterval(async () => {
      try {
        const info = await onSelectBackend(selectedBackend);
        setBackendSystemInfo(info);
      } catch { /* ignore */ }
    }, 60000);
    return () => clearInterval(interval);
  }, [selectedBackend, onSelectBackend]);

  if (!activeInfo) {
    return null;
  }

  // Calculate CPU load percentage (load average / total cores * 100)
  // Load average can exceed 100% if there are more processes than cores
  const cpuLoad1min = activeInfo.cpuLoad1min || 0;
  const cpuLoadPercent = activeInfo.totalCpus > 0
    ? Math.min((cpuLoad1min / activeInfo.totalCpus) * 100, 100)
    : 0;

  // Calculate percentages
  const memoryUsed = (activeInfo.totalMemoryBytes || 0) - (activeInfo.availableMemoryBytes || 0);
  const memoryPercent = activeInfo.totalMemoryBytes
    ? (memoryUsed / activeInfo.totalMemoryBytes) * 100
    : 0;

  const diskUsed = (activeInfo.totalDiskBytes || 0) - (activeInfo.availableDiskBytes || 0);
  const diskPercent = activeInfo.totalDiskBytes
    ? (diskUsed / activeInfo.totalDiskBytes) * 100
    : 0;

  // Check if we have resource data
  const hasResourceData = activeInfo.totalCpus > 0 || activeInfo.totalMemoryBytes > 0 || activeInfo.totalDiskBytes > 0;
  const showBackendSelector = backends && backends.length > 1;

  if (!hasResourceData) {
    return null;
  }

  return (
    <Card sx={{ mb: 3 }}>
      <CardContent sx={{ py: 2, '&:last-child': { pb: 2 } }}>
        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 1 }}>
          <Typography variant="subtitle2" color="text.secondary">
            System Resources{activeInfo.hostname ? ` — ${activeInfo.hostname}` : ''}
          </Typography>
          {showBackendSelector && (
            <ToggleButtonGroup
              value={selectedBackend}
              exclusive
              onChange={handleBackendChange}
              size="small"
              sx={{ '& .MuiToggleButton-root': { py: 0.25, px: 1.5, fontSize: '0.75rem' } }}
            >
              {backends.map(b => (
                <ToggleButton key={b.id} value={b.id} disabled={!b.healthy}>
                  {b.id}
                </ToggleButton>
              ))}
            </ToggleButtonGroup>
          )}
        </Box>
        <Grid container spacing={3}>
          {/* CPU */}
          {activeInfo.totalCpus > 0 && (
            <Grid item xs={12} sm={4}>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 0.5 }}>
                <ComputerIcon fontSize="small" color="action" />
                <Typography variant="body2" fontWeight="medium">
                  CPU Load
                </Typography>
              </Box>
              <Box sx={{ display: 'flex', alignItems: 'baseline', gap: 1 }}>
                <Typography variant="h6">
                  {cpuLoad1min.toFixed(2)}
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  / {activeInfo.totalCpus} cores
                </Typography>
              </Box>
              <Tooltip title={`${cpuLoadPercent.toFixed(1)}% utilized (1-min avg)`}>
                <LinearProgress
                  variant="determinate"
                  value={cpuLoadPercent}
                  color={getUsageColor(cpuLoadPercent)}
                  sx={{ mt: 0.5, height: 6, borderRadius: 3 }}
                />
              </Tooltip>
            </Grid>
          )}

          {/* Memory */}
          {activeInfo.totalMemoryBytes > 0 && (
            <Grid item xs={12} sm={4}>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 0.5 }}>
                <MemoryIcon fontSize="small" color="action" />
                <Typography variant="body2" fontWeight="medium">
                  Memory
                </Typography>
              </Box>
              <Box sx={{ display: 'flex', alignItems: 'baseline', gap: 1 }}>
                <Typography variant="h6">
                  {formatBytes(memoryUsed)}
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  / {formatBytes(activeInfo.totalMemoryBytes)}
                </Typography>
              </Box>
              <Tooltip title={`${memoryPercent.toFixed(1)}% used`}>
                <LinearProgress
                  variant="determinate"
                  value={memoryPercent}
                  color={getUsageColor(memoryPercent)}
                  sx={{ mt: 0.5, height: 6, borderRadius: 3 }}
                />
              </Tooltip>
            </Grid>
          )}

          {/* Disk */}
          {activeInfo.totalDiskBytes > 0 && (
            <Grid item xs={12} sm={4}>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 0.5 }}>
                <StorageIcon fontSize="small" color="action" />
                <Typography variant="body2" fontWeight="medium">
                  Storage
                </Typography>
              </Box>
              <Box sx={{ display: 'flex', alignItems: 'baseline', gap: 1 }}>
                <Typography variant="h6">
                  {formatBytes(diskUsed)}
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  / {formatBytes(activeInfo.totalDiskBytes)}
                </Typography>
              </Box>
              <Tooltip title={`${diskPercent.toFixed(1)}% used`}>
                <LinearProgress
                  variant="determinate"
                  value={diskPercent}
                  color={getUsageColor(diskPercent)}
                  sx={{ mt: 0.5, height: 6, borderRadius: 3 }}
                />
              </Tooltip>
            </Grid>
          )}

          {/* GPU */}
          {activeInfo.gpus && activeInfo.gpus.length > 0 && activeInfo.gpus.map((gpu, idx) => (
            <Grid item xs={12} sm={4} key={gpu.pciAddress || idx}>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 0.5 }}>
                <GpuIcon fontSize="small" color="action" />
                <Typography variant="body2" fontWeight="medium">
                  GPU{activeInfo.gpus!.length > 1 ? ` #${idx}` : ''}
                </Typography>
              </Box>
              <Box sx={{ display: 'flex', alignItems: 'baseline', gap: 1 }}>
                <Typography variant="h6">
                  {gpuModelDisplayName(gpu.model, gpu.modelName)}
                </Typography>
              </Box>
              <Typography variant="caption" color="text.secondary">
                {gpuVendorDisplayName(gpu.vendor)}
                {gpu.driverVersion ? ` \u00B7 Driver ${gpu.driverVersion}` : ''}
                {gpu.cudaVersion ? ` \u00B7 CUDA ${gpu.cudaVersion}` : ''}
                {gpu.vramBytes > 0 ? ` \u00B7 ${formatBytes(gpu.vramBytes)} VRAM` : ''}
              </Typography>
            </Grid>
          ))}
        </Grid>
      </CardContent>
    </Card>
  );
}
