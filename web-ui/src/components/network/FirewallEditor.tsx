'use client';

import { useState } from 'react';
import {
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Button,
  Box,
  Typography,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Chip,
  Paper,
  Alert,
  Tabs,
  Tab,
  CircularProgress,
} from '@mui/material';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import BlockIcon from '@mui/icons-material/Block';
import {
  NetworkACL,
  ACLRule,
  ACLPreset,
  ACLPresetInfo,
  getACLPresetName,
  getACLActionDisplay,
} from '@/src/types/app';

interface FirewallEditorProps {
  open: boolean;
  onClose: () => void;
  acl: NetworkACL | null;
  presets: ACLPresetInfo[];
  isLoading: boolean;
  appName: string;
  username: string;
  onSave: (preset: ACLPreset) => Promise<void>;
}

function RulesTable({ rules, title }: { rules: ACLRule[]; title: string }) {
  if (rules.length === 0) {
    return (
      <Box sx={{ p: 2, textAlign: 'center' }}>
        <Typography variant="body2" color="text.secondary">
          No {title.toLowerCase()} rules configured
        </Typography>
      </Box>
    );
  }

  return (
    <TableContainer>
      <Table size="small">
        <TableHead>
          <TableRow>
            <TableCell width={80}>Action</TableCell>
            <TableCell>Source/Destination</TableCell>
            <TableCell width={100}>Port</TableCell>
            <TableCell width={80}>Protocol</TableCell>
            <TableCell>Description</TableCell>
          </TableRow>
        </TableHead>
        <TableBody>
          {rules.map((rule, index) => {
            const actionDisplay = getACLActionDisplay(rule.action);
            return (
              <TableRow key={index}>
                <TableCell>
                  <Chip
                    icon={
                      rule.action === 'ACL_ACTION_ALLOW' ? (
                        <CheckCircleIcon sx={{ fontSize: 14 }} />
                      ) : (
                        <BlockIcon sx={{ fontSize: 14 }} />
                      )
                    }
                    label={actionDisplay.label}
                    color={actionDisplay.color}
                    size="small"
                    variant="outlined"
                  />
                </TableCell>
                <TableCell>
                  <Typography variant="body2" fontFamily="monospace">
                    {rule.source || rule.destination || '*'}
                  </Typography>
                </TableCell>
                <TableCell>
                  <Typography variant="body2" fontFamily="monospace">
                    {rule.destinationPort || '*'}
                  </Typography>
                </TableCell>
                <TableCell>
                  <Typography variant="body2">
                    {rule.protocol || 'any'}
                  </Typography>
                </TableCell>
                <TableCell>
                  <Typography variant="body2" color="text.secondary">
                    {rule.description}
                  </Typography>
                </TableCell>
              </TableRow>
            );
          })}
        </TableBody>
      </Table>
    </TableContainer>
  );
}

function PresetSelector({
  presets,
  selectedPreset,
  onSelect,
}: {
  presets: ACLPresetInfo[];
  selectedPreset: ACLPreset;
  onSelect: (preset: ACLPreset) => void;
}) {
  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
      {presets.map((preset) => {
        const isSelected = preset.preset === selectedPreset;
        return (
          <Paper
            key={preset.preset}
            sx={{
              p: 2,
              cursor: 'pointer',
              border: 2,
              borderColor: isSelected ? 'primary.main' : 'transparent',
              bgcolor: isSelected ? 'primary.50' : 'background.paper',
              '&:hover': {
                borderColor: isSelected ? 'primary.main' : 'grey.300',
              },
            }}
            onClick={() => onSelect(preset.preset)}
          >
            <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <Box>
                <Typography variant="subtitle1" fontWeight={600}>
                  {preset.name}
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  {preset.description}
                </Typography>
              </Box>
              {isSelected && (
                <CheckCircleIcon color="primary" />
              )}
            </Box>
          </Paper>
        );
      })}
    </Box>
  );
}

export default function FirewallEditor({
  open,
  onClose,
  acl,
  presets,
  isLoading,
  appName,
  username,
  onSave,
}: FirewallEditorProps) {
  const [selectedPreset, setSelectedPreset] = useState<ACLPreset>(
    acl?.preset || 'ACL_PRESET_FULL_ISOLATION'
  );
  const [tabValue, setTabValue] = useState(0);
  const [saving, setSaving] = useState(false);

  // Find the selected preset info to show preview rules
  const selectedPresetInfo = presets.find((p) => p.preset === selectedPreset);

  const handleSave = async () => {
    setSaving(true);
    try {
      await onSave(selectedPreset);
      onClose();
    } catch (error) {
      console.error('Failed to save ACL:', error);
    } finally {
      setSaving(false);
    }
  };

  return (
    <Dialog open={open} onClose={onClose} maxWidth="md" fullWidth>
      <DialogTitle>
        Firewall Settings - {appName}
        <Typography variant="body2" color="text.secondary">
          Owner: {username}
        </Typography>
      </DialogTitle>

      <DialogContent>
        {isLoading ? (
          <Box sx={{ display: 'flex', justifyContent: 'center', py: 4 }}>
            <CircularProgress />
          </Box>
        ) : (
          <>
            <Alert severity="info" sx={{ mb: 3 }}>
              Firewall rules control network traffic to and from your application container.
              We recommend using <strong>Full Isolation</strong> for production apps.
            </Alert>

            <Tabs value={tabValue} onChange={(_, v) => setTabValue(v)} sx={{ mb: 2 }}>
              <Tab label="Choose Preset" />
              <Tab label="Preview Rules" />
              {acl && <Tab label="Current Rules" />}
            </Tabs>

            {tabValue === 0 && (
              <PresetSelector
                presets={presets.filter((p) => p.preset !== 'ACL_PRESET_CUSTOM')}
                selectedPreset={selectedPreset}
                onSelect={setSelectedPreset}
              />
            )}

            {tabValue === 1 && selectedPresetInfo && (
              <Box>
                <Typography variant="subtitle2" gutterBottom>
                  Ingress Rules (Incoming Traffic)
                </Typography>
                <Paper variant="outlined" sx={{ mb: 3 }}>
                  <RulesTable rules={selectedPresetInfo.defaultIngressRules} title="ingress" />
                </Paper>

                <Typography variant="subtitle2" gutterBottom>
                  Egress Rules (Outgoing Traffic)
                </Typography>
                <Paper variant="outlined">
                  <RulesTable rules={selectedPresetInfo.defaultEgressRules} title="egress" />
                </Paper>
              </Box>
            )}

            {tabValue === 2 && acl && (
              <Box>
                <Box sx={{ mb: 2 }}>
                  <Typography variant="body2" color="text.secondary">
                    Current preset: <strong>{getACLPresetName(acl.preset)}</strong>
                  </Typography>
                </Box>

                <Typography variant="subtitle2" gutterBottom>
                  Ingress Rules (Incoming Traffic)
                </Typography>
                <Paper variant="outlined" sx={{ mb: 3 }}>
                  <RulesTable rules={acl.ingressRules} title="ingress" />
                </Paper>

                <Typography variant="subtitle2" gutterBottom>
                  Egress Rules (Outgoing Traffic)
                </Typography>
                <Paper variant="outlined">
                  <RulesTable rules={acl.egressRules} title="egress" />
                </Paper>
              </Box>
            )}
          </>
        )}
      </DialogContent>

      <DialogActions>
        <Button onClick={onClose} disabled={saving}>
          Cancel
        </Button>
        <Button
          onClick={handleSave}
          variant="contained"
          disabled={saving || isLoading}
        >
          {saving ? 'Saving...' : 'Apply Preset'}
        </Button>
      </DialogActions>
    </Dialog>
  );
}
