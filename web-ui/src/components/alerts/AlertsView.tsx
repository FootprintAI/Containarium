'use client';

import { useState } from 'react';
import {
  Box,
  Typography,
  IconButton,
  Button,
  Paper,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Chip,
  CircularProgress,
  Alert,
  Stack,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  MenuItem,
  Select,
  FormControl,
  InputLabel,
  Switch,
  FormControlLabel,
  Snackbar,
  Tooltip,
  Card,
  CardContent,
  Tabs,
  Tab,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  InputAdornment,
} from '@mui/material';
import RefreshIcon from '@mui/icons-material/Refresh';
import AddIcon from '@mui/icons-material/Add';
import DeleteIcon from '@mui/icons-material/Delete';
import EditIcon from '@mui/icons-material/Edit';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import ErrorIcon from '@mui/icons-material/Error';
import LockIcon from '@mui/icons-material/Lock';
import ContentCopyIcon from '@mui/icons-material/ContentCopy';
import VpnKeyIcon from '@mui/icons-material/VpnKey';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import { Server } from '@/src/types/server';
import { AlertRule, CreateAlertRuleRequest } from '@/src/types/alerts';
import SendIcon from '@mui/icons-material/Send';
import InfoOutlinedIcon from '@mui/icons-material/InfoOutlined';
import { useAlerts, useAlertingInfo, useDefaultAlertRules, useWebhookDeliveries } from '@/src/lib/hooks/useAlerts';
import { getClient } from '@/src/lib/api/client';

interface AlertsViewProps {
  server: Server;
}

function SeverityChip({ severity }: { severity: string }) {
  const colorMap: Record<string, 'error' | 'warning' | 'info' | 'default'> = {
    critical: 'error',
    warning: 'warning',
    info: 'info',
  };
  return (
    <Chip
      label={severity}
      size="small"
      color={colorMap[severity] || 'default'}
      variant="outlined"
    />
  );
}

function StatusIndicator({ status }: { status: string }) {
  const isHealthy = status === 'healthy';
  return (
    <Stack direction="row" spacing={0.5} alignItems="center">
      {isHealthy ? (
        <CheckCircleIcon sx={{ fontSize: 16, color: 'success.main' }} />
      ) : (
        <ErrorIcon sx={{ fontSize: 16, color: 'error.main' }} />
      )}
      <Typography variant="body2" color={isHealthy ? 'success.main' : 'error.main'}>
        {status || 'unknown'}
      </Typography>
    </Stack>
  );
}

function formatTimestamp(unix: string): string {
  if (!unix || unix === '0') return '-';
  try {
    return new Date(Number(unix) * 1000).toLocaleString();
  } catch {
    return unix;
  }
}

const EMPTY_RULE: CreateAlertRuleRequest = {
  name: '',
  expr: '',
  duration: '5m',
  severity: 'warning',
  description: '',
  enabled: true,
};

export default function AlertsView({ server }: AlertsViewProps) {
  const { rules, isLoading, error, refresh } = useAlerts(server);
  const { info, refresh: refreshInfo } = useAlertingInfo(server);
  const { rules: defaultRules } = useDefaultAlertRules(server);
  const { deliveries, refresh: refreshDeliveries } = useWebhookDeliveries(server);

  const [ruleTab, setRuleTab] = useState(0);
  const [dialogOpen, setDialogOpen] = useState(false);
  const [editingRule, setEditingRule] = useState<AlertRule | null>(null);
  const [formData, setFormData] = useState<CreateAlertRuleRequest>(EMPTY_RULE);
  const [saving, setSaving] = useState(false);
  const [snackMessage, setSnackMessage] = useState<string | null>(null);
  const [deleteConfirm, setDeleteConfirm] = useState<string | null>(null);
  const [webhookDialogOpen, setWebhookDialogOpen] = useState(false);
  const [webhookUrl, setWebhookUrl] = useState('');
  const [savingWebhook, setSavingWebhook] = useState(false);
  const [testingWebhook, setTestingWebhook] = useState(false);
  const [generatingSecret, setGeneratingSecret] = useState(false);
  const [generatedSecret, setGeneratedSecret] = useState<string | null>(null);
  const [detailRule, setDetailRule] = useState<AlertRule | null>(null);

  const handleOpenCreate = () => {
    setEditingRule(null);
    setFormData(EMPTY_RULE);
    setDialogOpen(true);
  };

  const handleOpenEdit = (rule: AlertRule) => {
    setEditingRule(rule);
    setFormData({
      name: rule.name,
      expr: rule.expr,
      duration: rule.duration,
      severity: rule.severity,
      description: rule.description,
      enabled: rule.enabled,
    });
    setDialogOpen(true);
  };

  const handleSave = async () => {
    setSaving(true);
    try {
      const client = getClient(server);
      if (editingRule) {
        await client.updateAlertRule(editingRule.id, formData);
        setSnackMessage('Alert rule updated');
      } else {
        await client.createAlertRule(formData);
        setSnackMessage('Alert rule created');
      }
      setDialogOpen(false);
      refresh();
      refreshInfo();
    } catch (err) {
      setSnackMessage(`Error: ${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setSaving(false);
    }
  };

  const handleDelete = async (id: string) => {
    try {
      const client = getClient(server);
      await client.deleteAlertRule(id);
      setSnackMessage('Alert rule deleted');
      setDeleteConfirm(null);
      refresh();
      refreshInfo();
    } catch (err) {
      setSnackMessage(`Error: ${err instanceof Error ? err.message : String(err)}`);
    }
  };

  const handleToggleEnabled = async (rule: AlertRule) => {
    try {
      const client = getClient(server);
      await client.updateAlertRule(rule.id, { enabled: !rule.enabled });
      refresh();
    } catch (err) {
      setSnackMessage(`Error: ${err instanceof Error ? err.message : String(err)}`);
    }
  };

  const handleSaveWebhook = async () => {
    setSavingWebhook(true);
    try {
      const client = getClient(server);
      await client.updateAlertingConfig(webhookUrl);
      setSnackMessage(webhookUrl ? 'Webhook URL updated' : 'Webhook disabled');
      setWebhookDialogOpen(false);
      refreshInfo();
    } catch (err) {
      setSnackMessage(`Error: ${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setSavingWebhook(false);
    }
  };

  const handleTestWebhook = async () => {
    setTestingWebhook(true);
    try {
      const client = getClient(server);
      const result = await client.testWebhook();
      setSnackMessage(result.message);
    } catch (err) {
      setSnackMessage(`Error: ${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setTestingWebhook(false);
    }
  };

  const handleGenerateSecret = async () => {
    setGeneratingSecret(true);
    try {
      const client = getClient(server);
      const result = await client.updateAlertingConfig(webhookUrl || info?.webhookUrl || '', true);
      if (result.webhookSecret) {
        setGeneratedSecret(result.webhookSecret);
        setSnackMessage('Webhook secret generated. Copy it now — it will not be shown again.');
      } else {
        setSnackMessage('Secret generated but not returned. Check server logs.');
      }
      refreshInfo();
    } catch (err) {
      setSnackMessage(`Error: ${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setGeneratingSecret(false);
    }
  };

  const handleCopySecret = () => {
    if (generatedSecret) {
      navigator.clipboard.writeText(generatedSecret);
      setSnackMessage('Secret copied to clipboard');
    }
  };

  if (isLoading) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', p: 4 }}>
        <CircularProgress />
      </Box>
    );
  }

  if (error) {
    return (
      <Box sx={{ p: 3 }}>
        <Alert severity="error">Failed to load alerts: {error.message}</Alert>
      </Box>
    );
  }

  return (
    <Box sx={{ p: 3 }}>
      {/* Header */}
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
        <Typography variant="h5">Alerts</Typography>
        <Stack direction="row" spacing={1}>
          <Button
            variant="contained"
            startIcon={<AddIcon />}
            onClick={handleOpenCreate}
            size="small"
          >
            Create Rule
          </Button>
          <IconButton onClick={() => { refresh(); refreshInfo(); refreshDeliveries(); }} size="small">
            <RefreshIcon />
          </IconButton>
        </Stack>
      </Box>

      {/* Status Cards */}
      {info && (
        <Stack direction="row" spacing={2} sx={{ mb: 3, flexWrap: 'wrap' }}>
          <Card sx={{ minWidth: 160 }}>
            <CardContent sx={{ py: 1.5, '&:last-child': { pb: 1.5 } }}>
              <Typography variant="caption" color="text.secondary">vmalert</Typography>
              <StatusIndicator status={info.vmalertStatus} />
            </CardContent>
          </Card>
          <Card sx={{ minWidth: 160 }}>
            <CardContent sx={{ py: 1.5, '&:last-child': { pb: 1.5 } }}>
              <Typography variant="caption" color="text.secondary">Alertmanager</Typography>
              <StatusIndicator status={info.alertmanagerStatus} />
            </CardContent>
          </Card>
          <Card sx={{ minWidth: 160 }}>
            <CardContent sx={{ py: 1.5, '&:last-child': { pb: 1.5 } }}>
              <Typography variant="caption" color="text.secondary">Total Rules</Typography>
              <Typography variant="h6">{info.totalRules}</Typography>
            </CardContent>
          </Card>
          <Card sx={{ minWidth: 160 }}>
            <CardContent sx={{ py: 1.5, '&:last-child': { pb: 1.5 } }}>
              <Typography variant="caption" color="text.secondary">Custom Rules</Typography>
              <Typography variant="h6">{info.customRules}</Typography>
            </CardContent>
          </Card>
          <Card
            sx={{ minWidth: 200, cursor: 'pointer', '&:hover': { bgcolor: 'action.hover' } }}
            onClick={() => { setWebhookUrl(''); setGeneratedSecret(null); setWebhookDialogOpen(true); }}
          >
            <CardContent sx={{ py: 1.5, '&:last-child': { pb: 1.5 } }}>
              <Typography variant="caption" color="text.secondary">Webhook Target</Typography>
              <Typography variant="body2" noWrap>
                {info.webhookUrl || 'Not configured (click to set)'}
              </Typography>
            </CardContent>
          </Card>
        </Stack>
      )}

      {/* Rules Tabs */}
      <Tabs value={ruleTab} onChange={(_, v) => setRuleTab(v)} sx={{ mb: 2 }}>
        <Tab label={`Default Rules (${defaultRules.length})`} />
        <Tab label={`Custom Rules (${rules.length})`} />
        <Tab label={`Delivery History (${deliveries.length})`} />
      </Tabs>

      {/* Default Rules Table */}
      {ruleTab === 0 && (
        <TableContainer component={Paper} variant="outlined">
          <Table size="small">
            <TableHead>
              <TableRow>
                <TableCell>Name</TableCell>
                <TableCell>Expression</TableCell>
                <TableCell>Duration</TableCell>
                <TableCell>Severity</TableCell>
                <TableCell>Status</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {defaultRules.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={5} align="center" sx={{ py: 4 }}>
                    <CircularProgress size={20} />
                  </TableCell>
                </TableRow>
              ) : (
                defaultRules.map((rule) => (
                  <TableRow key={rule.id} hover sx={{ cursor: 'pointer' }} onClick={() => setDetailRule(rule)}>
                    <TableCell>
                      <Stack direction="row" spacing={0.5} alignItems="center">
                        <LockIcon sx={{ fontSize: 14, color: 'text.disabled' }} />
                        <Box>
                          <Typography variant="body2" fontWeight={500}>{rule.name}</Typography>
                          {rule.description && (
                            <Typography variant="caption" color="text.secondary" display="block" sx={{ maxWidth: 400 }}>
                              {rule.description}
                            </Typography>
                          )}
                        </Box>
                      </Stack>
                    </TableCell>
                    <TableCell>
                      <Tooltip title={rule.expr}>
                        <Typography variant="body2" sx={{ fontFamily: 'monospace', fontSize: '0.8rem', maxWidth: 350, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                          {rule.expr}
                        </Typography>
                      </Tooltip>
                    </TableCell>
                    <TableCell>{rule.duration}</TableCell>
                    <TableCell><SeverityChip severity={rule.severity} /></TableCell>
                    <TableCell>
                      <Chip label="Always Active" size="small" color="success" variant="outlined" />
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </TableContainer>
      )}

      {/* Custom Rules Table */}
      {ruleTab === 1 && (
        <TableContainer component={Paper} variant="outlined">
          <Table size="small">
            <TableHead>
              <TableRow>
                <TableCell>Name</TableCell>
                <TableCell>Expression</TableCell>
                <TableCell>Duration</TableCell>
                <TableCell>Severity</TableCell>
                <TableCell>Enabled</TableCell>
                <TableCell>Created</TableCell>
                <TableCell align="right">Actions</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {rules.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={7} align="center" sx={{ py: 4 }}>
                    <Typography color="text.secondary">
                      No custom alert rules. Click &quot;Create Rule&quot; to add one.
                    </Typography>
                  </TableCell>
                </TableRow>
              ) : (
                rules.map((rule) => (
                  <TableRow key={rule.id} hover>
                    <TableCell sx={{ cursor: 'pointer' }} onClick={() => setDetailRule(rule)}>
                      <Typography variant="body2" fontWeight={500}>{rule.name}</Typography>
                      {rule.description && (
                        <Typography variant="caption" color="text.secondary" display="block">
                          {rule.description}
                        </Typography>
                      )}
                    </TableCell>
                    <TableCell sx={{ cursor: 'pointer' }} onClick={() => setDetailRule(rule)}>
                      <Typography variant="body2" sx={{ fontFamily: 'monospace', fontSize: '0.8rem', maxWidth: 300, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {rule.expr}
                      </Typography>
                    </TableCell>
                    <TableCell>{rule.duration}</TableCell>
                    <TableCell><SeverityChip severity={rule.severity} /></TableCell>
                    <TableCell>
                      <Switch
                        size="small"
                        checked={rule.enabled}
                        onChange={() => handleToggleEnabled(rule)}
                      />
                    </TableCell>
                    <TableCell>
                      <Typography variant="caption">{formatTimestamp(rule.createdAt)}</Typography>
                    </TableCell>
                    <TableCell align="right">
                      <Tooltip title="Edit">
                        <IconButton size="small" onClick={() => handleOpenEdit(rule)}>
                          <EditIcon fontSize="small" />
                        </IconButton>
                      </Tooltip>
                      <Tooltip title="Delete">
                        <IconButton size="small" color="error" onClick={() => setDeleteConfirm(rule.id)}>
                          <DeleteIcon fontSize="small" />
                        </IconButton>
                      </Tooltip>
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </TableContainer>
      )}

      {/* Delivery History Table */}
      {ruleTab === 2 && (
        <TableContainer component={Paper} variant="outlined">
          <Table size="small">
            <TableHead>
              <TableRow>
                <TableCell>Time</TableCell>
                <TableCell>Alert</TableCell>
                <TableCell>Source</TableCell>
                <TableCell>Status</TableCell>
                <TableCell>HTTP Code</TableCell>
                <TableCell>Duration</TableCell>
                <TableCell>Error</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {deliveries.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={7} align="center" sx={{ py: 4 }}>
                    <Typography color="text.secondary">
                      No delivery history yet. Send a test webhook or wait for alerts to fire.
                    </Typography>
                  </TableCell>
                </TableRow>
              ) : (
                deliveries.map((d) => (
                  <TableRow key={d.id} hover>
                    <TableCell>
                      <Typography variant="caption">
                        {d.timestamp ? new Date(d.timestamp).toLocaleString() : '-'}
                      </Typography>
                    </TableCell>
                    <TableCell>
                      <Typography variant="body2" fontWeight={500}>
                        {d.alertName || '-'}
                      </Typography>
                    </TableCell>
                    <TableCell>
                      <Chip
                        label={d.source}
                        size="small"
                        color={d.source === 'test' ? 'info' : 'default'}
                        variant="outlined"
                        icon={d.source === 'test' ? <SendIcon sx={{ fontSize: 14 }} /> : undefined}
                      />
                    </TableCell>
                    <TableCell>
                      {d.success ? (
                        <CheckCircleIcon sx={{ fontSize: 18, color: 'success.main' }} />
                      ) : (
                        <ErrorIcon sx={{ fontSize: 18, color: 'error.main' }} />
                      )}
                    </TableCell>
                    <TableCell>
                      <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>
                        {d.httpStatus || '-'}
                      </Typography>
                    </TableCell>
                    <TableCell>
                      <Typography variant="caption">{d.durationMs}ms</Typography>
                    </TableCell>
                    <TableCell>
                      {d.errorMessage && (
                        <Tooltip title={d.errorMessage}>
                          <Typography variant="caption" color="error" sx={{ maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', display: 'block' }}>
                            {d.errorMessage}
                          </Typography>
                        </Tooltip>
                      )}
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </TableContainer>
      )}

      {/* Create/Edit Dialog */}
      <Dialog open={dialogOpen} onClose={() => setDialogOpen(false)} maxWidth="sm" fullWidth>
        <DialogTitle>{editingRule ? 'Edit Alert Rule' : 'Create Alert Rule'}</DialogTitle>
        <DialogContent>
          <Stack spacing={2} sx={{ mt: 1 }}>
            <TextField
              label="Name"
              value={formData.name}
              onChange={(e) => setFormData({ ...formData, name: e.target.value })}
              fullWidth
              required
              placeholder="e.g. HighMemoryUsage"
            />
            <TextField
              label="PromQL Expression"
              value={formData.expr}
              onChange={(e) => setFormData({ ...formData, expr: e.target.value })}
              fullWidth
              required
              multiline
              rows={2}
              placeholder="e.g. system_memory_used_bytes / system_memory_total_bytes * 100 > 90"
              sx={{ '& textarea': { fontFamily: 'monospace', fontSize: '0.85rem' } }}
            />
            <Stack direction="row" spacing={2}>
              <TextField
                label="Duration"
                value={formData.duration}
                onChange={(e) => setFormData({ ...formData, duration: e.target.value })}
                placeholder="5m"
                sx={{ width: 120 }}
              />
              <FormControl sx={{ width: 150 }}>
                <InputLabel>Severity</InputLabel>
                <Select
                  value={formData.severity}
                  label="Severity"
                  onChange={(e) => setFormData({ ...formData, severity: e.target.value })}
                >
                  <MenuItem value="critical">Critical</MenuItem>
                  <MenuItem value="warning">Warning</MenuItem>
                  <MenuItem value="info">Info</MenuItem>
                </Select>
              </FormControl>
              <FormControlLabel
                control={
                  <Switch
                    checked={formData.enabled}
                    onChange={(e) => setFormData({ ...formData, enabled: e.target.checked })}
                  />
                }
                label="Enabled"
              />
            </Stack>
            <TextField
              label="Description"
              value={formData.description || ''}
              onChange={(e) => setFormData({ ...formData, description: e.target.value })}
              fullWidth
              multiline
              rows={2}
              placeholder="Describe what this alert means and when it fires"
            />
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDialogOpen(false)}>Cancel</Button>
          <Button
            onClick={handleSave}
            variant="contained"
            disabled={saving || !formData.name || !formData.expr}
          >
            {saving ? <CircularProgress size={20} /> : editingRule ? 'Update' : 'Create'}
          </Button>
        </DialogActions>
      </Dialog>

      {/* Webhook Configuration Dialog */}
      <Dialog open={webhookDialogOpen} onClose={() => setWebhookDialogOpen(false)} maxWidth="md" fullWidth>
        <DialogTitle>Configure Webhook</DialogTitle>
        <DialogContent>
          <Stack spacing={2} sx={{ mt: 1 }}>
            <Typography variant="body2" color="text.secondary">
              Set a webhook URL to receive alert notifications. Alerts will be sent as HTTP POST requests
              in Alertmanager webhook format. Leave empty to disable notifications.
            </Typography>
            {info?.webhookUrl && (
              <Alert severity="info" variant="outlined">
                Current webhook: {info.webhookUrl}
              </Alert>
            )}
            <TextField
              label="Webhook URL"
              value={webhookUrl}
              onChange={(e) => setWebhookUrl(e.target.value)}
              fullWidth
              placeholder="https://hooks.slack.com/services/... or https://your-endpoint.com/alerts"
              helperText="Supports any HTTP endpoint that accepts POST requests (Slack, PagerDuty, custom webhook, etc.)"
            />

            {/* Webhook Secret Section */}
            <Box sx={{ border: 1, borderColor: 'divider', borderRadius: 1, p: 2 }}>
              <Stack direction="row" spacing={1} alignItems="center" sx={{ mb: 1 }}>
                <VpnKeyIcon sx={{ fontSize: 18, color: 'text.secondary' }} />
                <Typography variant="subtitle2">HMAC Signing Secret</Typography>
                {info?.webhookSecretConfigured ? (
                  <Chip label="Configured" size="small" color="success" variant="outlined" />
                ) : (
                  <Chip label="Not set" size="small" color="default" variant="outlined" />
                )}
              </Stack>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 1.5 }}>
                When configured, all webhook payloads are signed with HMAC-SHA256.
                The signature is sent in the <code>X-Containarium-Signature</code> header.
              </Typography>
              <Button
                variant="outlined"
                size="small"
                onClick={handleGenerateSecret}
                disabled={generatingSecret}
                startIcon={generatingSecret ? <CircularProgress size={16} /> : <VpnKeyIcon />}
              >
                {info?.webhookSecretConfigured ? 'Rotate Secret' : 'Generate Secret'}
              </Button>

              {/* Show generated secret (one-time display) */}
              {generatedSecret && (
                <Alert severity="warning" sx={{ mt: 1.5 }}>
                  <Typography variant="body2" fontWeight={600} sx={{ mb: 0.5 }}>
                    Copy this secret now. It will not be shown again.
                  </Typography>
                  <TextField
                    value={generatedSecret}
                    fullWidth
                    size="small"
                    InputProps={{
                      readOnly: true,
                      sx: { fontFamily: 'monospace', fontSize: '0.85rem' },
                      endAdornment: (
                        <InputAdornment position="end">
                          <IconButton size="small" onClick={handleCopySecret}>
                            <ContentCopyIcon fontSize="small" />
                          </IconButton>
                        </InputAdornment>
                      ),
                    }}
                  />
                </Alert>
              )}
            </Box>

            {/* How to verify webhooks */}
            <Accordion variant="outlined" disableGutters>
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Typography variant="subtitle2">How to verify webhooks</Typography>
              </AccordionSummary>
              <AccordionDetails>
                <Stack spacing={2}>
                  <Typography variant="body2" color="text.secondary">
                    Containarium sends a <code>X-Containarium-Signature</code> header with each webhook POST.
                    The format is <code>sha256=&lt;hex-encoded HMAC-SHA256&gt;</code> computed over the raw request body.
                  </Typography>

                  <Box>
                    <Typography variant="caption" fontWeight={600}>Python</Typography>
                    <Box component="pre" sx={{ bgcolor: 'grey.100', p: 1.5, borderRadius: 1, overflow: 'auto', fontSize: '0.8rem', fontFamily: 'monospace' }}>
{`import hmac, hashlib

def verify(body: bytes, secret: str, signature: str) -> bool:
    expected = "sha256=" + hmac.new(
        secret.encode(), body, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, signature)`}
                    </Box>
                  </Box>

                  <Box>
                    <Typography variant="caption" fontWeight={600}>Go</Typography>
                    <Box component="pre" sx={{ bgcolor: 'grey.100', p: 1.5, borderRadius: 1, overflow: 'auto', fontSize: '0.8rem', fontFamily: 'monospace' }}>
{`import (
    "crypto/hmac"
    "crypto/sha256"
    "encoding/hex"
)

func verify(body []byte, secret, signature string) bool {
    mac := hmac.New(sha256.New, []byte(secret))
    mac.Write(body)
    expected := "sha256=" + hex.EncodeToString(mac.Sum(nil))
    return hmac.Equal([]byte(expected), []byte(signature))
}`}
                    </Box>
                  </Box>

                  <Box>
                    <Typography variant="caption" fontWeight={600}>Node.js</Typography>
                    <Box component="pre" sx={{ bgcolor: 'grey.100', p: 1.5, borderRadius: 1, overflow: 'auto', fontSize: '0.8rem', fontFamily: 'monospace' }}>
{`const crypto = require('crypto');

function verify(body, secret, signature) {
  const expected = 'sha256=' + crypto
    .createHmac('sha256', secret)
    .update(body)
    .digest('hex');
  return crypto.timingSafeEqual(
    Buffer.from(expected), Buffer.from(signature)
  );
}`}
                    </Box>
                  </Box>
                </Stack>
              </AccordionDetails>
            </Accordion>
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setWebhookDialogOpen(false)}>Cancel</Button>
          {info?.webhookUrl && (
            <Button
              onClick={handleTestWebhook}
              disabled={testingWebhook}
              color="secondary"
            >
              {testingWebhook ? <CircularProgress size={20} /> : 'Send Test'}
            </Button>
          )}
          {info?.webhookUrl && (
            <Button
              onClick={() => { setWebhookUrl(''); handleSaveWebhook(); }}
              color="error"
              disabled={savingWebhook}
            >
              Disable
            </Button>
          )}
          <Button
            onClick={handleSaveWebhook}
            variant="contained"
            disabled={savingWebhook || !webhookUrl}
          >
            {savingWebhook ? <CircularProgress size={20} /> : 'Save'}
          </Button>
        </DialogActions>
      </Dialog>

      {/* Delete Confirmation */}
      <Dialog open={!!deleteConfirm} onClose={() => setDeleteConfirm(null)}>
        <DialogTitle>Delete Alert Rule</DialogTitle>
        <DialogContent>
          <Typography>Are you sure you want to delete this alert rule? This cannot be undone.</Typography>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDeleteConfirm(null)}>Cancel</Button>
          <Button
            onClick={() => deleteConfirm && handleDelete(deleteConfirm)}
            color="error"
            variant="contained"
          >
            Delete
          </Button>
        </DialogActions>
      </Dialog>

      {/* Rule Detail Dialog */}
      <Dialog open={!!detailRule} onClose={() => setDetailRule(null)} maxWidth="md" fullWidth>
        {detailRule && (
          <>
            <DialogTitle>
              <Stack direction="row" spacing={1} alignItems="center">
                <InfoOutlinedIcon color="primary" />
                <Typography variant="h6">{detailRule.name}</Typography>
                <SeverityChip severity={detailRule.severity} />
              </Stack>
            </DialogTitle>
            <DialogContent>
              <Stack spacing={2.5} sx={{ mt: 1 }}>
                {detailRule.description && (
                  <Box>
                    <Typography variant="subtitle2" color="text.secondary" gutterBottom>Description</Typography>
                    <Typography variant="body2">{detailRule.description}</Typography>
                  </Box>
                )}

                <Box>
                  <Typography variant="subtitle2" color="text.secondary" gutterBottom>PromQL Expression</Typography>
                  <Box sx={{ bgcolor: 'grey.100', p: 2, borderRadius: 1, fontFamily: 'monospace', fontSize: '0.85rem', overflowX: 'auto', whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>
                    {detailRule.expr}
                  </Box>
                </Box>

                <Stack direction="row" spacing={4}>
                  <Box>
                    <Typography variant="subtitle2" color="text.secondary" gutterBottom>Duration (for)</Typography>
                    <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>{detailRule.duration}</Typography>
                  </Box>
                  <Box>
                    <Typography variant="subtitle2" color="text.secondary" gutterBottom>Severity</Typography>
                    <SeverityChip severity={detailRule.severity} />
                  </Box>
                  <Box>
                    <Typography variant="subtitle2" color="text.secondary" gutterBottom>Status</Typography>
                    <Chip
                      label={detailRule.enabled ? 'Enabled' : 'Disabled'}
                      size="small"
                      color={detailRule.enabled ? 'success' : 'default'}
                      variant="outlined"
                    />
                  </Box>
                </Stack>

                {detailRule.labels && Object.keys(detailRule.labels).length > 0 && (
                  <Box>
                    <Typography variant="subtitle2" color="text.secondary" gutterBottom>Labels</Typography>
                    <Stack direction="row" spacing={0.5} flexWrap="wrap" useFlexGap>
                      {Object.entries(detailRule.labels).map(([k, v]) => (
                        <Chip key={k} label={`${k}=${v}`} size="small" variant="outlined" sx={{ fontFamily: 'monospace', fontSize: '0.8rem' }} />
                      ))}
                    </Stack>
                  </Box>
                )}

                {detailRule.annotations && Object.keys(detailRule.annotations).length > 0 && (
                  <Box>
                    <Typography variant="subtitle2" color="text.secondary" gutterBottom>Annotations</Typography>
                    <Stack spacing={0.5}>
                      {Object.entries(detailRule.annotations).map(([k, v]) => (
                        <Box key={k}>
                          <Typography variant="caption" color="text.secondary" sx={{ fontFamily: 'monospace' }}>{k}:</Typography>
                          <Typography variant="body2" sx={{ ml: 1 }}>{v}</Typography>
                        </Box>
                      ))}
                    </Stack>
                  </Box>
                )}

                {/* How this rule works */}
                <Accordion variant="outlined" disableGutters>
                  <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                    <Typography variant="subtitle2">How this rule works</Typography>
                  </AccordionSummary>
                  <AccordionDetails>
                    <Stack spacing={1.5}>
                      <Typography variant="body2" color="text.secondary">
                        This alert fires when the PromQL expression evaluates to <strong>true</strong> continuously
                        for the specified duration (<code>{detailRule.duration}</code>).
                      </Typography>
                      <Box>
                        <Typography variant="caption" fontWeight={600}>Equivalent vmalert YAML</Typography>
                        <Box component="pre" sx={{ bgcolor: 'grey.100', p: 1.5, borderRadius: 1, overflow: 'auto', fontSize: '0.8rem', fontFamily: 'monospace' }}>
{`- alert: ${detailRule.name}
  expr: ${detailRule.expr}
  for: ${detailRule.duration}
  labels:
    severity: ${detailRule.severity}${detailRule.labels && Object.keys(detailRule.labels).length > 0 ? '\n' + Object.entries(detailRule.labels).map(([k, v]) => `    ${k}: ${v}`).join('\n') : ''}
  annotations:
    summary: "${detailRule.description || detailRule.name}"${detailRule.annotations && Object.keys(detailRule.annotations).length > 0 ? '\n' + Object.entries(detailRule.annotations).map(([k, v]) => `    ${k}: "${v}"`).join('\n') : ''}`}
                        </Box>
                      </Box>
                      <Box>
                        <Typography variant="caption" fontWeight={600}>Writing PromQL Expressions</Typography>
                        <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5 }}>
                          Expressions use metrics collected by VictoriaMetrics. Common patterns:
                        </Typography>
                        <Box component="pre" sx={{ bgcolor: 'grey.100', p: 1.5, borderRadius: 1, overflow: 'auto', fontSize: '0.8rem', fontFamily: 'monospace', mt: 0.5 }}>
{`# System metrics
system_memory_used_bytes / system_memory_total_bytes * 100 > 90
system_cpu_load_5m / system_cpu_cores * 100 > 80
system_disk_used_bytes / system_disk_total_bytes * 100 > 85

# Container metrics (use label filters)
container_memory_usage_bytes{name="mycontainer"} > 3.5e9
container_cpu_usage_percent{name=~".*-container"} > 90
container_state{state="Stopped"} == 1

# Rate and aggregation
rate(container_network_rx_bytes[5m]) > 1e8
count(container_state{state="Running"}) == 0`}
                        </Box>
                      </Box>
                    </Stack>
                  </AccordionDetails>
                </Accordion>
              </Stack>
            </DialogContent>
            <DialogActions>
              <Button onClick={() => setDetailRule(null)}>Close</Button>
            </DialogActions>
          </>
        )}
      </Dialog>

      {/* Snackbar */}
      <Snackbar
        open={!!snackMessage}
        autoHideDuration={4000}
        onClose={() => setSnackMessage(null)}
        message={snackMessage}
      />
    </Box>
  );
}
