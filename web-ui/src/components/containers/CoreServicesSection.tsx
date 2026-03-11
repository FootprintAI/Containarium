'use client';

import {
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Typography,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Chip,
  Box,
} from '@mui/material';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import { CoreService } from '@/src/lib/api/client';

const ROLE_DISPLAY_NAMES: Record<string, string> = {
  'core-postgres': 'PostgreSQL',
  'core-caddy': 'Caddy',
  'core-victoriametrics': 'VictoriaMetrics',
  'core-security': 'ClamAV',
};

function displayName(role: string): string {
  return ROLE_DISPLAY_NAMES[role] || role;
}

function stateColor(state: string): 'success' | 'error' | 'default' {
  if (state === 'Running') return 'success';
  if (state === 'Stopped' || state === 'Error') return 'error';
  return 'default';
}

interface CoreServicesSectionProps {
  services: CoreService[];
}

export default function CoreServicesSection({ services }: CoreServicesSectionProps) {
  if (services.length === 0) return null;

  return (
    <Accordion defaultExpanded={false} sx={{ mb: 2 }}>
      <AccordionSummary expandIcon={<ExpandMoreIcon />}>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <Typography variant="subtitle1" fontWeight={600}>
            Core Infrastructure
          </Typography>
          <Chip label={`${services.length} services`} size="small" variant="outlined" />
        </Box>
      </AccordionSummary>
      <AccordionDetails sx={{ p: 0 }}>
        <TableContainer>
          <Table size="small">
            <TableHead>
              <TableRow>
                <TableCell>Service</TableCell>
                <TableCell>Status</TableCell>
                <TableCell>IP Address</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {services.map((svc) => (
                <TableRow key={svc.name}>
                  <TableCell>
                    <Typography variant="body2" fontWeight={500}>
                      {displayName(svc.role)}
                    </Typography>
                    <Typography variant="caption" color="text.secondary">
                      {svc.name}
                    </Typography>
                  </TableCell>
                  <TableCell>
                    <Chip
                      label={svc.state}
                      size="small"
                      color={stateColor(svc.state)}
                    />
                  </TableCell>
                  <TableCell>
                    <Typography variant="body2" fontFamily="monospace">
                      {svc.ipAddress || '-'}
                    </Typography>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
      </AccordionDetails>
    </Accordion>
  );
}
