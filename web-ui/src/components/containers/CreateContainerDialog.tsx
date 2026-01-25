'use client';

import { useState } from 'react';
import {
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  Button,
  Alert,
  CircularProgress,
  Box,
  FormControlLabel,
  Checkbox,
  MenuItem,
  Select,
  InputLabel,
  FormControl,
  LinearProgress,
  Typography,
} from '@mui/material';
import DownloadIcon from '@mui/icons-material/Download';
import { CreateContainerRequest } from '@/src/types/container';
import { generateSSHKeyPair, downloadPrivateKey, SSHKeyPair } from '@/src/lib/sshkey';
import { CreateContainerProgress } from '@/src/lib/hooks/useContainers';

interface CreateContainerDialogProps {
  open: boolean;
  onClose: () => void;
  onSubmit: (request: CreateContainerRequest, onProgress?: (progress: CreateContainerProgress) => void) => Promise<unknown>;
  networkCidr?: string; // Network CIDR from server (e.g., "10.100.0.0/24")
}

const IMAGES = [
  { value: 'images:ubuntu/24.04', label: 'Ubuntu 24.04' },
  { value: 'images:ubuntu/22.04', label: 'Ubuntu 22.04' },
  { value: 'images:debian/12', label: 'Debian 12' },
  { value: 'images:alpine/3.19', label: 'Alpine 3.19' },
];

// Default network CIDR (used when server doesn't provide one)
const DEFAULT_NETWORK_CIDR = '10.100.0.0/24';

/**
 * Parse IPv4 address to numeric value
 */
function ipToNumber(ip: string): number | null {
  const parts = ip.split('.');
  if (parts.length !== 4) return null;

  let result = 0;
  for (const part of parts) {
    const num = parseInt(part, 10);
    if (isNaN(num) || num < 0 || num > 255) return null;
    result = result * 256 + num;
  }
  return result;
}

/**
 * Validate if an IP address is within a CIDR range
 */
function isIPInCIDR(ip: string, cidr: string): boolean {
  const [networkAddr, prefix] = cidr.split('/');
  const prefixLen = parseInt(prefix, 10);

  if (isNaN(prefixLen) || prefixLen < 0 || prefixLen > 32) return false;

  const ipNum = ipToNumber(ip);
  const networkNum = ipToNumber(networkAddr);

  if (ipNum === null || networkNum === null) return false;

  const mask = ~((1 << (32 - prefixLen)) - 1) >>> 0;
  return (ipNum & mask) === (networkNum & mask);
}

/**
 * Validate a static IP address format and range
 */
function validateStaticIP(ip: string, cidr: string): { valid: boolean; error?: string } {
  if (!ip) return { valid: true }; // Empty is valid (DHCP)

  // Check basic format
  const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
  if (!ipRegex.test(ip)) {
    return { valid: false, error: 'Invalid IP address format' };
  }

  // Check each octet is valid
  const parts = ip.split('.');
  for (const part of parts) {
    const num = parseInt(part, 10);
    if (num < 0 || num > 255) {
      return { valid: false, error: 'Invalid IP address: octets must be 0-255' };
    }
  }

  // Check if IP is within the network CIDR
  if (!isIPInCIDR(ip, cidr)) {
    return { valid: false, error: `IP must be within network ${cidr}` };
  }

  // Check if it's not the gateway or broadcast address
  const networkParts = cidr.split('/')[0].split('.');
  const gatewayIP = [...networkParts.slice(0, 3), '1'].join('.');
  const broadcastIP = [...networkParts.slice(0, 3), '255'].join('.');

  if (ip === gatewayIP) {
    return { valid: false, error: 'Cannot use gateway IP address' };
  }
  if (ip === broadcastIP) {
    return { valid: false, error: 'Cannot use broadcast IP address' };
  }

  return { valid: true };
}

export default function CreateContainerDialog({ open, onClose, onSubmit, networkCidr }: CreateContainerDialogProps) {
  // Use provided network CIDR or default
  const effectiveCidr = networkCidr || DEFAULT_NETWORK_CIDR;

  const [username, setUsername] = useState('');
  const [image, setImage] = useState('images:ubuntu/24.04');
  const [cpu, setCpu] = useState('4');
  const [memory, setMemory] = useState('4GB');
  const [disk, setDisk] = useState('50GB');
  const [staticIp, setStaticIp] = useState('');
  const [staticIpError, setStaticIpError] = useState<string | null>(null);
  const [autoGenerateKey, setAutoGenerateKey] = useState(true);
  const [sshPublicKey, setSshPublicKey] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState(false);
  const [generatedKeyPair, setGeneratedKeyPair] = useState<SSHKeyPair | null>(null);
  const [progress, setProgress] = useState<CreateContainerProgress | null>(null);

  const resetForm = () => {
    setUsername('');
    setImage('images:ubuntu/24.04');
    setCpu('4');
    setMemory('4GB');
    setDisk('50GB');
    setStaticIp('');
    setStaticIpError(null);
    setAutoGenerateKey(true);
    setSshPublicKey('');
    setSubmitting(false);
    setError(null);
    setSuccess(false);
    setGeneratedKeyPair(null);
    setProgress(null);
  };

  const handleClose = () => {
    if (submitting) return; // Prevent closing while creating
    resetForm();
    onClose();
  };

  const handleDownloadKey = () => {
    if (generatedKeyPair) {
      downloadPrivateKey(generatedKeyPair.privateKey, username + '-container.pem');
    }
  };

  const handleSubmit = async () => {
    if (!username) {
      setError('Please enter a username');
      return;
    }

    if (!autoGenerateKey && !sshPublicKey) {
      setError('Please enter an SSH public key or enable auto-generate');
      return;
    }

    // Validate static IP if provided
    if (staticIp) {
      const validation = validateStaticIP(staticIp, effectiveCidr);
      if (!validation.valid) {
        setError(validation.error || 'Invalid static IP address');
        return;
      }
    }

    setSubmitting(true);
    setError(null);
    setProgress({ state: 'Creating', message: 'Preparing...' });

    try {
      let publicKey = sshPublicKey;

      // Generate SSH key pair if auto-generate is enabled
      if (autoGenerateKey) {
        setProgress({ state: 'Creating', message: 'Generating SSH key pair...' });
        const keyPair = await generateSSHKeyPair(username);
        publicKey = keyPair.publicKey;
        setGeneratedKeyPair(keyPair);
      }

      const request: CreateContainerRequest = {
        username,
        image,
        resources: {
          cpu,
          memory,
          disk,
        },
        sshKeys: [publicKey],
        enableDocker: true,
        staticIp: staticIp || undefined,
      };

      const container = await onSubmit(request, (prog) => {
        setProgress(prog);
      });

      // Check if the container ended up in an error state
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const containerState = (container as any)?.state;
      if (containerState === 'Error') {
        setError('Container creation failed. Check server logs for details.');
        setGeneratedKeyPair(null);
        setProgress(null);
        return;
      }

      setSuccess(true);
      setProgress({ state: 'Running', message: 'Container is ready!' });
    } catch (err) {
      setError('Failed to create container: ' + String(err));
      setGeneratedKeyPair(null);
      setProgress(null);
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <Dialog open={open} onClose={handleClose} maxWidth="sm" fullWidth>
      <DialogTitle>Create Container</DialogTitle>
      <DialogContent>
        <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2, mt: 1 }}>
          {error && (
            <Alert severity="error" onClose={() => setError(null)}>
              {error}
            </Alert>
          )}

          {submitting && progress && (
            <Box sx={{ width: '100%' }}>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
                <CircularProgress size={16} />
                <Typography variant="body2" color="text.secondary">
                  {progress.message}
                </Typography>
              </Box>
              <LinearProgress />
            </Box>
          )}

          {success && generatedKeyPair && (
            <Alert
              severity="success"
              action={
                <Button
                  color="inherit"
                  size="small"
                  startIcon={<DownloadIcon />}
                  onClick={handleDownloadKey}
                >
                  Download Key
                </Button>
              }
            >
              Container created! Download your private key now (it will not be shown again).
            </Alert>
          )}

          {success && !generatedKeyPair && (
            <Alert severity="success">
              Container created successfully!
            </Alert>
          )}

          <TextField
            label="Username / Container Name"
            value={username}
            onChange={(e) => setUsername(e.target.value.toLowerCase().replace(/[^a-z0-9-]/g, ''))}
            placeholder="mycontainer"
            required
            fullWidth
            disabled={success || submitting}
            helperText="Lowercase letters, numbers, and hyphens only"
          />

          <FormControl fullWidth disabled={success || submitting}>
            <InputLabel>Image</InputLabel>
            <Select
              value={image}
              label="Image"
              onChange={(e) => setImage(e.target.value)}
            >
              {IMAGES.map((img) => (
                <MenuItem key={img.value} value={img.value}>
                  {img.label}
                </MenuItem>
              ))}
            </Select>
          </FormControl>

          <Box sx={{ display: 'flex', gap: 2 }}>
            <TextField
              label="CPU Cores"
              value={cpu}
              onChange={(e) => setCpu(e.target.value)}
              placeholder="4"
              fullWidth
              disabled={success || submitting}
            />
            <TextField
              label="Memory"
              value={memory}
              onChange={(e) => setMemory(e.target.value)}
              placeholder="4GB"
              fullWidth
              disabled={success || submitting}
            />
            <TextField
              label="Disk"
              value={disk}
              onChange={(e) => setDisk(e.target.value)}
              placeholder="50GB"
              fullWidth
              disabled={success || submitting}
            />
          </Box>

          <TextField
            label="Static IP (Optional)"
            value={staticIp}
            onChange={(e) => {
              const value = e.target.value.replace(/[^0-9.]/g, '');
              setStaticIp(value);
              if (value) {
                const validation = validateStaticIP(value, effectiveCidr);
                setStaticIpError(validation.error || null);
              } else {
                setStaticIpError(null);
              }
            }}
            placeholder="Leave empty for DHCP"
            fullWidth
            disabled={success || submitting}
            error={!!staticIpError}
            helperText={staticIpError || `e.g., 10.100.0.100 - must be within ${effectiveCidr}`}
          />

          <FormControlLabel
            control={
              <Checkbox
                checked={autoGenerateKey}
                onChange={(e) => setAutoGenerateKey(e.target.checked)}
                disabled={success || submitting}
              />
            }
            label="Auto-generate SSH key pair"
          />

          {!autoGenerateKey && (
            <TextField
              label="SSH Public Key"
              value={sshPublicKey}
              onChange={(e) => setSshPublicKey(e.target.value)}
              placeholder="ssh-ed25519 AAAA... user@host"
              multiline
              rows={3}
              fullWidth
              disabled={success || submitting}
            />
          )}
        </Box>
      </DialogContent>
      <DialogActions>
        <Button onClick={handleClose} disabled={submitting}>
          {success ? 'Close' : 'Cancel'}
        </Button>
        {!success && (
          <Button
            variant="contained"
            onClick={handleSubmit}
            disabled={submitting || !username || !!staticIpError}
          >
            {submitting ? 'Creating...' : 'Create'}
          </Button>
        )}
      </DialogActions>
    </Dialog>
  );
}
