'use client';

import { useState } from 'react';
import {
  Box,
  Typography,
  Button,
  CircularProgress,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
} from '@mui/material';
import RefreshIcon from '@mui/icons-material/Refresh';
import { App } from '@/src/types/app';
import AppCard from './AppCard';

interface AppsViewProps {
  apps: App[];
  isLoading: boolean;
  error?: Error | null;
  onStopApp: (username: string, appName: string) => Promise<void>;
  onStartApp: (username: string, appName: string) => Promise<void>;
  onRestartApp: (username: string, appName: string) => Promise<void>;
  onDeleteApp: (username: string, appName: string) => Promise<void>;
  onViewLogs?: (username: string, appName: string) => void;
  onRefresh: () => void;
}

export default function AppsView({
  apps,
  isLoading,
  error,
  onStopApp,
  onStartApp,
  onRestartApp,
  onDeleteApp,
  onViewLogs,
  onRefresh,
}: AppsViewProps) {
  const [deleteDialog, setDeleteDialog] = useState<{ open: boolean; username: string; appName: string }>({
    open: false,
    username: '',
    appName: '',
  });
  const [confirmText, setConfirmText] = useState('');

  const handleDeleteClick = (username: string, appName: string) => {
    setDeleteDialog({ open: true, username, appName });
    setConfirmText('');
  };

  const handleDeleteConfirm = async () => {
    if (confirmText === deleteDialog.appName) {
      await onDeleteApp(deleteDialog.username, deleteDialog.appName);
      setDeleteDialog({ open: false, username: '', appName: '' });
    }
  };

  if (isLoading && apps.length === 0) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', minHeight: 300 }}>
        <CircularProgress />
      </Box>
    );
  }

  if (error) {
    return (
      <Box sx={{ p: 3, textAlign: 'center' }}>
        <Typography color="error" gutterBottom>
          Failed to load apps
        </Typography>
        <Typography variant="body2" color="text.secondary">
          {error.message}
        </Typography>
        <Button onClick={onRefresh} sx={{ mt: 2 }}>
          Retry
        </Button>
      </Box>
    );
  }

  return (
    <Box sx={{ p: 3 }}>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
        <Typography variant="h5">
          Applications ({apps.length})
        </Typography>
        <Box sx={{ display: 'flex', gap: 1 }}>
          <Button
            variant="outlined"
            startIcon={<RefreshIcon />}
            onClick={onRefresh}
            disabled={isLoading}
          >
            Refresh
          </Button>
        </Box>
      </Box>

      {apps.length === 0 ? (
        <Box sx={{ textAlign: 'center', py: 6 }}>
          <Typography color="text.secondary" gutterBottom>
            No applications found
          </Typography>
          <Typography variant="body2" color="text.secondary">
            Deploy your first app using the CLI:
          </Typography>
          <Box
            component="pre"
            sx={{
              mt: 2,
              p: 2,
              bgcolor: 'grey.100',
              borderRadius: 1,
              display: 'inline-block',
              textAlign: 'left',
            }}
          >
            containarium app deploy myapp --source .
          </Box>
        </Box>
      ) : (
        <Box
          sx={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fill, minmax(350px, 1fr))',
            gap: 2,
          }}
        >
          {apps.map((app) => (
            <AppCard
              key={app.id}
              app={app}
              onStop={onStopApp}
              onStart={onStartApp}
              onRestart={onRestartApp}
              onDelete={handleDeleteClick}
              onViewLogs={onViewLogs}
            />
          ))}
        </Box>
      )}

      {/* Delete Confirmation Dialog */}
      <Dialog open={deleteDialog.open} onClose={() => setDeleteDialog({ open: false, username: '', appName: '' })}>
        <DialogTitle>Delete Application</DialogTitle>
        <DialogContent>
          <Typography gutterBottom>
            Are you sure you want to delete <strong>{deleteDialog.appName}</strong>?
          </Typography>
          <Typography variant="body2" color="text.secondary" gutterBottom>
            This action cannot be undone. Type the app name to confirm:
          </Typography>
          <TextField
            fullWidth
            size="small"
            placeholder={deleteDialog.appName}
            value={confirmText}
            onChange={(e) => setConfirmText(e.target.value)}
            sx={{ mt: 2 }}
          />
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDeleteDialog({ open: false, username: '', appName: '' })}>
            Cancel
          </Button>
          <Button
            onClick={handleDeleteConfirm}
            color="error"
            disabled={confirmText !== deleteDialog.appName}
          >
            Delete
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
}
