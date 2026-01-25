'use client';

import { Box, Card, CardContent, Typography, LinearProgress, Grid, Tooltip } from '@mui/material';
import MemoryIcon from '@mui/icons-material/Memory';
import StorageIcon from '@mui/icons-material/Storage';
import ComputerIcon from '@mui/icons-material/Computer';
import { SystemInfo } from '@/src/types/container';

interface SystemResourcesCardProps {
  systemInfo: SystemInfo | null;
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

export default function SystemResourcesCard({ systemInfo }: SystemResourcesCardProps) {
  if (!systemInfo) {
    return null;
  }

  // Calculate percentages
  const memoryUsed = (systemInfo.totalMemoryBytes || 0) - (systemInfo.availableMemoryBytes || 0);
  const memoryPercent = systemInfo.totalMemoryBytes
    ? (memoryUsed / systemInfo.totalMemoryBytes) * 100
    : 0;

  const diskUsed = (systemInfo.totalDiskBytes || 0) - (systemInfo.availableDiskBytes || 0);
  const diskPercent = systemInfo.totalDiskBytes
    ? (diskUsed / systemInfo.totalDiskBytes) * 100
    : 0;

  // Check if we have resource data
  const hasResourceData = systemInfo.totalCpus > 0 || systemInfo.totalMemoryBytes > 0 || systemInfo.totalDiskBytes > 0;

  if (!hasResourceData) {
    return null;
  }

  return (
    <Card sx={{ mb: 3 }}>
      <CardContent sx={{ py: 2, '&:last-child': { pb: 2 } }}>
        <Typography variant="subtitle2" color="text.secondary" gutterBottom>
          System Resources
        </Typography>
        <Grid container spacing={3}>
          {/* CPU */}
          {systemInfo.totalCpus > 0 && (
            <Grid item xs={12} sm={4}>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 0.5 }}>
                <ComputerIcon fontSize="small" color="action" />
                <Typography variant="body2" fontWeight="medium">
                  CPU Cores
                </Typography>
              </Box>
              <Typography variant="h6" color="primary">
                {systemInfo.totalCpus}
              </Typography>
              <Typography variant="caption" color="text.secondary">
                Available for containers
              </Typography>
            </Grid>
          )}

          {/* Memory */}
          {systemInfo.totalMemoryBytes > 0 && (
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
                  / {formatBytes(systemInfo.totalMemoryBytes)}
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
          {systemInfo.totalDiskBytes > 0 && (
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
                  / {formatBytes(systemInfo.totalDiskBytes)}
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
        </Grid>
      </CardContent>
    </Card>
  );
}
