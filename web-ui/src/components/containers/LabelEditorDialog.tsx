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
  Chip,
  IconButton,
  Typography,
  CircularProgress,
  Divider,
} from '@mui/material';
import AddIcon from '@mui/icons-material/Add';
import DeleteIcon from '@mui/icons-material/Delete';

interface LabelEditorDialogProps {
  open: boolean;
  onClose: () => void;
  containerName: string;
  username: string;
  currentLabels: Record<string, string>;
  onSave: (labels: Record<string, string>) => Promise<void>;
  onRemove: (key: string) => Promise<void>;
}

export default function LabelEditorDialog({
  open,
  onClose,
  containerName,
  username,
  currentLabels,
  onSave,
  onRemove,
}: LabelEditorDialogProps) {
  const [labels, setLabels] = useState<Record<string, string>>({});
  const [newKey, setNewKey] = useState('');
  const [newValue, setNewValue] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [removingKey, setRemovingKey] = useState<string | null>(null);

  // Initialize labels when dialog opens or currentLabels change
  useEffect(() => {
    if (open) {
      setLabels({ ...currentLabels });
      setNewKey('');
      setNewValue('');
      setError(null);
    }
  }, [open, currentLabels]);

  const handleAddLabel = () => {
    const key = newKey.trim();
    const value = newValue.trim();

    if (!key) {
      setError('Label key cannot be empty');
      return;
    }

    if (!value) {
      setError('Label value cannot be empty');
      return;
    }

    // Validate key format (alphanumeric, hyphens, underscores, dots)
    if (!/^[a-zA-Z0-9._-]+$/.test(key)) {
      setError('Label key can only contain letters, numbers, dots, hyphens, and underscores');
      return;
    }

    setLabels(prev => ({ ...prev, [key]: value }));
    setNewKey('');
    setNewValue('');
    setError(null);
  };

  const handleRemoveLabel = async (key: string) => {
    // If label exists on server, remove it
    if (currentLabels[key] !== undefined) {
      setRemovingKey(key);
      try {
        await onRemove(key);
        setLabels(prev => {
          const updated = { ...prev };
          delete updated[key];
          return updated;
        });
      } catch (err) {
        setError(`Failed to remove label: ${err}`);
      } finally {
        setRemovingKey(null);
      }
    } else {
      // Label only exists locally, just remove from state
      setLabels(prev => {
        const updated = { ...prev };
        delete updated[key];
        return updated;
      });
    }
  };

  const handleSave = async () => {
    // Find new or modified labels
    const labelsToSave: Record<string, string> = {};
    for (const [key, value] of Object.entries(labels)) {
      if (currentLabels[key] !== value) {
        labelsToSave[key] = value;
      }
    }

    if (Object.keys(labelsToSave).length === 0) {
      onClose();
      return;
    }

    setSaving(true);
    setError(null);

    try {
      await onSave(labelsToSave);
      onClose();
    } catch (err) {
      setError(`Failed to save labels: ${err}`);
    } finally {
      setSaving(false);
    }
  };

  const handleClose = () => {
    if (saving) return;
    onClose();
  };

  const hasChanges = () => {
    const currentKeys = Object.keys(currentLabels);
    const newKeys = Object.keys(labels);

    if (currentKeys.length !== newKeys.length) return true;

    for (const key of newKeys) {
      if (currentLabels[key] !== labels[key]) return true;
    }

    return false;
  };

  return (
    <Dialog open={open} onClose={handleClose} maxWidth="sm" fullWidth>
      <DialogTitle>
        Edit Labels
        <Typography variant="body2" color="text.secondary">
          {containerName}
        </Typography>
      </DialogTitle>
      <DialogContent>
        <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2, mt: 1 }}>
          {error && (
            <Alert severity="error" onClose={() => setError(null)}>
              {error}
            </Alert>
          )}

          {/* Current labels */}
          <Box>
            <Typography variant="subtitle2" gutterBottom>
              Current Labels
            </Typography>
            {Object.keys(labels).length === 0 ? (
              <Typography variant="body2" color="text.secondary">
                No labels set
              </Typography>
            ) : (
              <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1 }}>
                {Object.entries(labels).map(([key, value]) => (
                  <Chip
                    key={key}
                    label={`${key}=${value}`}
                    onDelete={() => handleRemoveLabel(key)}
                    deleteIcon={
                      removingKey === key ? (
                        <CircularProgress size={16} />
                      ) : (
                        <DeleteIcon />
                      )
                    }
                    disabled={removingKey === key}
                    color={currentLabels[key] !== value ? 'primary' : 'default'}
                    variant={currentLabels[key] === undefined ? 'filled' : 'outlined'}
                  />
                ))}
              </Box>
            )}
          </Box>

          <Divider />

          {/* Add new label */}
          <Box>
            <Typography variant="subtitle2" gutterBottom>
              Add New Label
            </Typography>
            <Box sx={{ display: 'flex', gap: 1, alignItems: 'flex-start' }}>
              <TextField
                label="Key"
                value={newKey}
                onChange={(e) => setNewKey(e.target.value)}
                placeholder="e.g., team"
                size="small"
                sx={{ flex: 1 }}
                disabled={saving}
                onKeyDown={(e) => {
                  if (e.key === 'Enter') {
                    e.preventDefault();
                    handleAddLabel();
                  }
                }}
              />
              <TextField
                label="Value"
                value={newValue}
                onChange={(e) => setNewValue(e.target.value)}
                placeholder="e.g., backend"
                size="small"
                sx={{ flex: 1 }}
                disabled={saving}
                onKeyDown={(e) => {
                  if (e.key === 'Enter') {
                    e.preventDefault();
                    handleAddLabel();
                  }
                }}
              />
              <IconButton
                color="primary"
                onClick={handleAddLabel}
                disabled={saving || !newKey.trim() || !newValue.trim()}
              >
                <AddIcon />
              </IconButton>
            </Box>
            <Typography variant="caption" color="text.secondary" sx={{ mt: 0.5 }}>
              Labels help organize and filter containers. Common keys: team, env, project, owner
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
          disabled={saving || !hasChanges()}
        >
          {saving ? 'Saving...' : 'Save Changes'}
        </Button>
      </DialogActions>
    </Dialog>
  );
}
