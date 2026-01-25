'use client';

import {
  Card,
  CardContent,
  CardActions,
  Typography,
  Chip,
  Box,
  IconButton,
  Tooltip,
  Link,
  Divider,
} from '@mui/material';
import PlayArrowIcon from '@mui/icons-material/PlayArrow';
import StopIcon from '@mui/icons-material/Stop';
import RestartAltIcon from '@mui/icons-material/RestartAlt';
import DeleteIcon from '@mui/icons-material/Delete';
import TerminalIcon from '@mui/icons-material/Terminal';
import SecurityIcon from '@mui/icons-material/Security';
import LanguageIcon from '@mui/icons-material/Language';
import StorageIcon from '@mui/icons-material/Storage';
import {
  App,
  getAppStateName,
  getAppStateColor,
  getACLPresetName,
} from '@/src/types/app';

interface AppCardProps {
  app: App;
  onStop: (username: string, appName: string) => void;
  onStart: (username: string, appName: string) => void;
  onRestart: (username: string, appName: string) => void;
  onDelete: (username: string, appName: string) => void;
  onViewLogs?: (username: string, appName: string) => void;
}

export default function AppCard({
  app,
  onStop,
  onStart,
  onRestart,
  onDelete,
  onViewLogs,
}: AppCardProps) {
  const isRunning = app.state === 'APP_STATE_RUNNING';
  const isStopped = app.state === 'APP_STATE_STOPPED';
  const isFailed = app.state === 'APP_STATE_FAILED';
  const isTransitioning = ['APP_STATE_UPLOADING', 'APP_STATE_BUILDING', 'APP_STATE_RESTARTING'].includes(app.state);

  return (
    <Card
      sx={{
        height: '100%',
        display: 'flex',
        flexDirection: 'column',
        borderLeft: 4,
        borderColor: isRunning
          ? 'success.main'
          : isFailed
          ? 'error.main'
          : isTransitioning
          ? 'warning.main'
          : 'grey.400',
      }}
    >
      <CardContent sx={{ flexGrow: 1, pb: 1 }}>
        {/* Header */}
        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', mb: 1 }}>
          <Box>
            <Typography variant="h6" component="div" sx={{ fontWeight: 600 }}>
              {app.name}
            </Typography>
            <Typography variant="body2" color="text.secondary">
              {app.username}
            </Typography>
          </Box>
          <Chip
            label={getAppStateName(app.state)}
            color={getAppStateColor(app.state)}
            size="small"
          />
        </Box>

        <Divider sx={{ my: 1.5 }} />

        {/* Domain */}
        <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
          <LanguageIcon sx={{ fontSize: 18, mr: 1, color: 'text.secondary' }} />
          <Typography variant="body2" color="text.secondary" sx={{ mr: 0.5 }}>
            Domain:
          </Typography>
          {isRunning ? (
            <Link
              href={`https://${app.fullDomain}`}
              target="_blank"
              rel="noopener noreferrer"
              sx={{ fontSize: '0.875rem' }}
            >
              {app.fullDomain}
            </Link>
          ) : (
            <Typography variant="body2">{app.fullDomain}</Typography>
          )}
        </Box>

        {/* Container IP */}
        {app.containerIp && (
          <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
            <StorageIcon sx={{ fontSize: 18, mr: 1, color: 'text.secondary' }} />
            <Typography variant="body2" color="text.secondary" sx={{ mr: 0.5 }}>
              Container:
            </Typography>
            <Typography variant="body2" fontFamily="monospace">
              {app.containerIp}:{app.port}
            </Typography>
          </Box>
        )}

        {/* Firewall (managed at container level) */}
        <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
          <SecurityIcon sx={{ fontSize: 18, mr: 1, color: 'text.secondary' }} />
          <Typography variant="body2" color="text.secondary" sx={{ mr: 0.5 }}>
            Firewall:
          </Typography>
          <Tooltip title="Firewall is managed at container level">
            <Chip
              label={getACLPresetName(app.aclPreset || 'ACL_PRESET_UNSPECIFIED')}
              size="small"
              variant="outlined"
              color={app.aclPreset === 'ACL_PRESET_FULL_ISOLATION' ? 'success' : 'default'}
            />
          </Tooltip>
        </Box>

        {/* Error message */}
        {isFailed && app.errorMessage && (
          <Box sx={{ mt: 1, p: 1, bgcolor: 'error.light', borderRadius: 1 }}>
            <Typography variant="body2" color="error.contrastText">
              {app.errorMessage}
            </Typography>
          </Box>
        )}

        {/* Resources */}
        {app.resources && (
          <Box sx={{ mt: 1 }}>
            <Typography variant="caption" color="text.secondary">
              Resources: {app.resources.cpu} CPU, {app.resources.memory} RAM
            </Typography>
          </Box>
        )}
      </CardContent>

      <CardActions sx={{ justifyContent: 'flex-end', px: 2, pb: 1.5 }}>
        {onViewLogs && (
          <Tooltip title="View Logs">
            <IconButton size="small" onClick={() => onViewLogs(app.username, app.name)}>
              <TerminalIcon fontSize="small" />
            </IconButton>
          </Tooltip>
        )}

        {isRunning && (
          <Tooltip title="Stop">
            <IconButton
              size="small"
              onClick={() => onStop(app.username, app.name)}
              color="warning"
            >
              <StopIcon fontSize="small" />
            </IconButton>
          </Tooltip>
        )}

        {isStopped && (
          <Tooltip title="Start">
            <IconButton
              size="small"
              onClick={() => onStart(app.username, app.name)}
              color="success"
            >
              <PlayArrowIcon fontSize="small" />
            </IconButton>
          </Tooltip>
        )}

        {(isRunning || isStopped) && (
          <Tooltip title="Restart">
            <IconButton
              size="small"
              onClick={() => onRestart(app.username, app.name)}
              disabled={isTransitioning}
            >
              <RestartAltIcon fontSize="small" />
            </IconButton>
          </Tooltip>
        )}

        <Tooltip title="Delete">
          <IconButton
            size="small"
            onClick={() => onDelete(app.username, app.name)}
            color="error"
          >
            <DeleteIcon fontSize="small" />
          </IconButton>
        </Tooltip>
      </CardActions>
    </Card>
  );
}
