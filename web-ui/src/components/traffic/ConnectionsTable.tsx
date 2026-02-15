'use client';

import React from 'react';
import {
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  Chip,
  Typography,
  Box,
  Tooltip,
} from '@mui/material';
import { Connection, formatBytes, formatDuration, getProtocolLabel, getStateLabel } from '@/src/types/traffic';

interface ConnectionsTableProps {
  connections: Connection[];
  isLoading?: boolean;
}

/**
 * Get chip color for protocol
 */
function getProtocolColor(protocol: string): 'primary' | 'secondary' | 'default' {
  switch (protocol) {
    case 'TCP':
      return 'primary';
    case 'UDP':
      return 'secondary';
    default:
      return 'default';
  }
}

/**
 * Get chip color for connection state
 */
function getStateColor(state: string): 'success' | 'warning' | 'error' | 'default' {
  switch (state) {
    case 'ESTABLISHED':
      return 'success';
    case 'SYN_SENT':
    case 'SYN_RECV':
    case 'NEW':
      return 'warning';
    case 'TIME_WAIT':
    case 'CLOSE_WAIT':
    case 'FIN_WAIT':
    case 'CLOSED':
      return 'error';
    default:
      return 'default';
  }
}

/**
 * Calculate connection duration from timestamps
 */
function getConnectionDuration(firstSeen: string, lastSeen: string): number {
  const start = new Date(firstSeen).getTime();
  const end = new Date(lastSeen).getTime();
  return Math.floor((end - start) / 1000);
}

export default function ConnectionsTable({ connections, isLoading }: ConnectionsTableProps) {
  if (isLoading) {
    return (
      <Box sx={{ p: 3, textAlign: 'center' }}>
        <Typography color="text.secondary">Loading connections...</Typography>
      </Box>
    );
  }

  if (connections.length === 0) {
    return (
      <Box sx={{ p: 3, textAlign: 'center' }}>
        <Typography color="text.secondary">No active connections</Typography>
      </Box>
    );
  }

  return (
    <TableContainer component={Paper} variant="outlined">
      <Table size="small">
        <TableHead>
          <TableRow>
            <TableCell>Protocol</TableCell>
            <TableCell>Destination</TableCell>
            <TableCell>Port</TableCell>
            <TableCell>State</TableCell>
            <TableCell align="right">Sent</TableCell>
            <TableCell align="right">Received</TableCell>
            <TableCell align="right">Duration</TableCell>
          </TableRow>
        </TableHead>
        <TableBody>
          {connections.map((conn) => (
            <TableRow
              key={conn.id}
              sx={{ '&:last-child td, &:last-child th': { border: 0 } }}
              hover
            >
              <TableCell>
                <Chip
                  label={getProtocolLabel(conn.protocol)}
                  size="small"
                  color={getProtocolColor(conn.protocol)}
                  variant="outlined"
                />
              </TableCell>
              <TableCell>
                <Tooltip title={`Source: ${conn.sourceIp}:${conn.sourcePort}`}>
                  <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>
                    {conn.destIp}
                  </Typography>
                </Tooltip>
              </TableCell>
              <TableCell>
                <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>
                  {conn.destPort}
                </Typography>
              </TableCell>
              <TableCell>
                <Chip
                  label={getStateLabel(conn.state)}
                  size="small"
                  color={getStateColor(conn.state)}
                  variant="filled"
                  sx={{ fontSize: '0.7rem' }}
                />
              </TableCell>
              <TableCell align="right">
                <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>
                  {formatBytes(conn.bytesSent)}
                </Typography>
              </TableCell>
              <TableCell align="right">
                <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>
                  {formatBytes(conn.bytesReceived)}
                </Typography>
              </TableCell>
              <TableCell align="right">
                <Typography variant="body2" color="text.secondary">
                  {formatDuration(getConnectionDuration(conn.firstSeen, conn.lastSeen))}
                </Typography>
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </TableContainer>
  );
}
