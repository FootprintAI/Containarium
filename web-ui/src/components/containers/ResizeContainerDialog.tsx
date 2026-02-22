'use client';

import { useState, useEffect } from 'react';
import {
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  Button,
  Alert,
  Box,
  Typography,
  Slider,
  Select,
  MenuItem,
  FormControl,
  InputLabel,
  InputAdornment,
} from '@mui/material';
import WarningIcon from '@mui/icons-material/Warning';

interface ResizeContainerDialogProps {
  open: boolean;
  onClose: () => void;
  containerName: string;
  username: string;
  currentCpu: string;
  currentMemory: string;
  currentDisk: string;
  memoryUsageBytes?: number;
  diskUsageBytes?: number;
  onResize: (resources: { cpu?: string; memory?: string; disk?: string }) => Promise<void>;
}

// Parse size string to value and unit (e.g., "4GB" -> { value: 4, unit: "GB" })
function parseSize(sizeStr: string): { value: number; unit: string } {
  if (!sizeStr) return { value: 0, unit: 'GB' };
  const match = sizeStr.match(/^([\d.]+)\s*(MB|GB|TB|M|G|T)?$/i);
  if (!match) return { value: 0, unit: 'GB' };
  const value = parseFloat(match[1]);
  let unit = (match[2] || 'GB').toUpperCase();
  // Normalize short units
  if (unit === 'M') unit = 'MB';
  if (unit === 'G') unit = 'GB';
  if (unit === 'T') unit = 'TB';
  return { value, unit };
}

// Convert to bytes for comparison
function toBytes(value: number, unit: string): number {
  const multipliers: Record<string, number> = {
    'MB': 1024 * 1024,
    'GB': 1024 * 1024 * 1024,
    'TB': 1024 * 1024 * 1024 * 1024,
  };
  return value * (multipliers[unit] || multipliers['GB']);
}

// Format bytes to human readable
function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

export default function ResizeContainerDialog({
  open,
  onClose,
  containerName,
  username,
  currentCpu,
  currentMemory,
  currentDisk,
  memoryUsageBytes,
  diskUsageBytes,
  onResize,
}: ResizeContainerDialogProps) {
  // CPU state
  const [cpuValue, setCpuValue] = useState(4);

  // Memory state
  const [memoryValue, setMemoryValue] = useState(4);
  const [memoryUnit, setMemoryUnit] = useState('GB');

  // Disk state
  const [diskValue, setDiskValue] = useState(50);
  const [diskUnit, setDiskUnit] = useState('GB');

  // Original values for comparison
  const [originalCpu, setOriginalCpu] = useState(4);
  const [originalMemoryBytes, setOriginalMemoryBytes] = useState(0);
  const [originalDiskBytes, setOriginalDiskBytes] = useState(0);

  // UI state
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  // Initialize values when dialog opens
  useEffect(() => {
    if (open) {
      // Parse CPU
      const cpu = parseInt(currentCpu) || 4;
      setCpuValue(cpu);
      setOriginalCpu(cpu);

      // Parse Memory
      const mem = parseSize(currentMemory);
      setMemoryValue(mem.value || 4);
      setMemoryUnit(mem.unit || 'GB');
      setOriginalMemoryBytes(toBytes(mem.value || 4, mem.unit || 'GB'));

      // Parse Disk
      const disk = parseSize(currentDisk);
      setDiskValue(disk.value || 50);
      setDiskUnit(disk.unit || 'GB');
      setOriginalDiskBytes(toBytes(disk.value || 50, disk.unit || 'GB'));

      setError(null);
    }
  }, [open, currentCpu, currentMemory, currentDisk]);

  const handleSave = async () => {
    const newCpu = cpuValue.toString();
    const newMemory = `${memoryValue}${memoryUnit}`;
    const newDisk = `${diskValue}${diskUnit}`;

    // Build resources object with only changed values
    const resources: { cpu?: string; memory?: string; disk?: string } = {};

    if (cpuValue !== originalCpu) {
      resources.cpu = newCpu;
    }

    const newMemoryBytes = toBytes(memoryValue, memoryUnit);
    if (newMemoryBytes !== originalMemoryBytes) {
      resources.memory = newMemory;
    }

    const newDiskBytes = toBytes(diskValue, diskUnit);
    if (newDiskBytes !== originalDiskBytes) {
      // Warn if trying to shrink disk
      if (newDiskBytes < originalDiskBytes) {
        setError('Disk size can only be increased, not decreased');
        return;
      }
      resources.disk = newDisk;
    }

    if (Object.keys(resources).length === 0) {
      onClose();
      return;
    }

    setSaving(true);
    setError(null);

    try {
      await onResize(resources);
      onClose();
    } catch (err) {
      setError(`Failed to resize container: ${err}`);
    } finally {
      setSaving(false);
    }
  };

  const handleClose = () => {
    if (saving) return;
    onClose();
  };

  const hasChanges = () => {
    if (cpuValue !== originalCpu) return true;
    if (toBytes(memoryValue, memoryUnit) !== originalMemoryBytes) return true;
    if (toBytes(diskValue, diskUnit) !== originalDiskBytes) return true;
    return false;
  };

  const isDiskShrinking = () => {
    return toBytes(diskValue, diskUnit) < originalDiskBytes;
  };

  // Slider marks for CPU
  const cpuMarks = [
    { value: 1, label: '1' },
    { value: 8, label: '8' },
    { value: 16, label: '16' },
    { value: 32, label: '32' },
  ];

  // Slider marks for Memory (in GB)
  const memoryMarks = [
    { value: 1, label: '1' },
    { value: 16, label: '16' },
    { value: 32, label: '32' },
    { value: 64, label: '64' },
  ];

  // Slider marks for Disk (in GB)
  const diskMarks = [
    { value: 10, label: '10' },
    { value: 100, label: '100' },
    { value: 250, label: '250' },
    { value: 500, label: '500' },
  ];

  return (
    <Dialog open={open} onClose={handleClose} maxWidth="sm" fullWidth>
      <DialogTitle>
        Resize Container
        <Typography variant="body2" color="text.secondary">
          {containerName}
        </Typography>
      </DialogTitle>
      <DialogContent>
        <Box sx={{ display: 'flex', flexDirection: 'column', gap: 3, mt: 1 }}>
          {error && (
            <Alert severity="error" onClose={() => setError(null)}>
              {error}
            </Alert>
          )}

          {/* CPU Section */}
          <Box>
            <Typography variant="subtitle2" gutterBottom>
              CPU Cores
            </Typography>
            <Box sx={{ px: 1 }}>
              <Slider
                value={cpuValue}
                onChange={(_, value) => setCpuValue(value as number)}
                min={1}
                max={32}
                step={1}
                marks={cpuMarks}
                valueLabelDisplay="auto"
                disabled={saving}
              />
            </Box>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mt: 1 }}>
              <TextField
                type="number"
                value={cpuValue}
                onChange={(e) => {
                  const val = parseInt(e.target.value) || 1;
                  setCpuValue(Math.min(Math.max(val, 1), 32));
                }}
                size="small"
                sx={{ width: 100 }}
                disabled={saving}
                InputProps={{
                  endAdornment: <InputAdornment position="end">cores</InputAdornment>,
                }}
              />
              {cpuValue !== originalCpu && (
                <Typography variant="caption" color="primary">
                  Changed from {originalCpu}
                </Typography>
              )}
            </Box>
          </Box>

          {/* Memory Section */}
          <Box>
            <Typography variant="subtitle2" gutterBottom>
              Memory
            </Typography>
            <Box sx={{ px: 1 }}>
              <Slider
                value={memoryUnit === 'GB' ? memoryValue : memoryValue / 1024}
                onChange={(_, value) => {
                  if (memoryUnit === 'GB') {
                    setMemoryValue(value as number);
                  } else {
                    setMemoryValue((value as number) * 1024);
                  }
                }}
                min={1}
                max={64}
                step={1}
                marks={memoryMarks}
                valueLabelDisplay="auto"
                valueLabelFormat={(v) => `${v} GB`}
                disabled={saving}
              />
            </Box>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mt: 1 }}>
              <TextField
                type="number"
                value={memoryValue}
                onChange={(e) => {
                  const val = parseFloat(e.target.value) || 1;
                  setMemoryValue(Math.max(val, 0.5));
                }}
                size="small"
                sx={{ width: 100 }}
                disabled={saving}
              />
              <FormControl size="small" sx={{ minWidth: 80 }}>
                <Select
                  value={memoryUnit}
                  onChange={(e) => setMemoryUnit(e.target.value)}
                  disabled={saving}
                >
                  <MenuItem value="MB">MB</MenuItem>
                  <MenuItem value="GB">GB</MenuItem>
                </Select>
              </FormControl>
              {memoryUsageBytes !== undefined && memoryUsageBytes > 0 && (
                <Typography variant="caption" color="text.secondary">
                  Using: {formatBytes(memoryUsageBytes)}
                </Typography>
              )}
            </Box>
          </Box>

          {/* Disk Section */}
          <Box>
            <Typography variant="subtitle2" gutterBottom>
              Disk Storage
            </Typography>
            <Box sx={{ px: 1 }}>
              <Slider
                value={diskUnit === 'GB' ? diskValue : diskValue * 1024}
                onChange={(_, value) => {
                  if (diskUnit === 'GB') {
                    setDiskValue(value as number);
                  } else {
                    setDiskValue((value as number) / 1024);
                  }
                }}
                min={10}
                max={500}
                step={10}
                marks={diskMarks}
                valueLabelDisplay="auto"
                valueLabelFormat={(v) => `${v} GB`}
                disabled={saving}
              />
            </Box>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mt: 1 }}>
              <TextField
                type="number"
                value={diskValue}
                onChange={(e) => {
                  const val = parseFloat(e.target.value) || 10;
                  setDiskValue(Math.max(val, 1));
                }}
                size="small"
                sx={{ width: 100 }}
                disabled={saving}
              />
              <FormControl size="small" sx={{ minWidth: 80 }}>
                <Select
                  value={diskUnit}
                  onChange={(e) => setDiskUnit(e.target.value)}
                  disabled={saving}
                >
                  <MenuItem value="GB">GB</MenuItem>
                  <MenuItem value="TB">TB</MenuItem>
                </Select>
              </FormControl>
              {diskUsageBytes !== undefined && diskUsageBytes > 0 && (
                <Typography variant="caption" color="text.secondary">
                  Using: {formatBytes(diskUsageBytes)}
                </Typography>
              )}
            </Box>
            {isDiskShrinking() && (
              <Alert severity="warning" icon={<WarningIcon />} sx={{ mt: 1 }}>
                Disk size can only be increased, not decreased
              </Alert>
            )}
            <Typography variant="caption" color="text.secondary" sx={{ mt: 0.5, display: 'block' }}>
              Note: Disk can only be increased. Changes take effect immediately without restart.
            </Typography>
          </Box>
        </Box>
      </DialogContent>
      <DialogActions>
        <Button onClick={handleClose} disabled={saving}>
          Cancel
        </Button>
        <Button
          variant="contained"
          onClick={handleSave}
          disabled={saving || !hasChanges() || isDiskShrinking()}
        >
          {saving ? 'Applying...' : 'Apply Changes'}
        </Button>
      </DialogActions>
    </Dialog>
  );
}
