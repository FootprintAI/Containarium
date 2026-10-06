'use client';

import { useState, useEffect, useCallback } from 'react';
import { RefreshCw, Loader2, CheckCircle2, AlertTriangle, HelpCircle } from 'lucide-react';
import { Server } from '@/src/types/server';
import { AgentEngine, AgentEngineReadiness, AgentEngineStatus, AgentCredentialSource, GatewayProvider } from '@/src/types/agents';
import { getClient } from '@/src/lib/api/client';

interface AgentEnginesPanelProps { server: Server; }

const ENGINE_LABELS: Record<AgentEngine, string> = {
  AGENT_ENGINE_UNSPECIFIED: 'Unspecified',
  AGENT_ENGINE_CLAUDE: 'Claude',
  AGENT_ENGINE_CODEX: 'Codex',
  AGENT_ENGINE_GEMINI: 'Gemini',
};

// Mirrors internal/gatewayprovider.Name() — same lowercase/hyphen spelling,
// so this label and the CLI's PROVIDER column never read differently for
// the same row.
const PROVIDER_LABELS: Record<GatewayProvider, string> = {
  GATEWAY_PROVIDER_UNSPECIFIED: '—',
  GATEWAY_PROVIDER_ANTHROPIC: 'anthropic',
  GATEWAY_PROVIDER_OPENAI: 'openai',
  GATEWAY_PROVIDER_GEMINI: 'gemini',
  GATEWAY_PROVIDER_GEMINI_OPENAI: 'gemini-openai',
  GATEWAY_PROVIDER_KAFEIDO: 'kafeido',
};

const SOURCE_LABELS: Record<AgentCredentialSource, string> = {
  AGENT_CREDENTIAL_SOURCE_UNSPECIFIED: '—',
  AGENT_CREDENTIAL_SOURCE_GLOBAL_KEY: 'global key',
  AGENT_CREDENTIAL_SOURCE_OWNER_KEY: 'your key',
  AGENT_CREDENTIAL_SOURCE_DIRECT_MODE: 'direct mode',
};

const GATEWAY_KEY_DOC_URL = 'https://github.com/FootprintAI/Containarium/blob/main/docs/AGENT-MODEL-GATEWAY-DESIGN.md';

function readinessBadge(readiness: AgentEngineReadiness) {
  switch (readiness) {
    case 'AGENT_ENGINE_READINESS_READY':
      return (
        <span className="inline-flex items-center gap-1 text-[var(--c-emerald)]">
          <CheckCircle2 className="h-3.5 w-3.5" /> ready
        </span>
      );
    case 'AGENT_ENGINE_READINESS_NOT_READY':
      return (
        <span className="inline-flex items-center gap-1 text-[var(--c-amber)]">
          <AlertTriangle className="h-3.5 w-3.5" /> not ready
        </span>
      );
    case 'AGENT_ENGINE_READINESS_UNKNOWN_DIRECT_MODE':
      return (
        <span className="inline-flex items-center gap-1 text-[var(--text-muted)]">
          <HelpCircle className="h-3.5 w-3.5" /> unknown (direct mode)
        </span>
      );
    default:
      return <span className="text-[var(--text-muted)]">—</span>;
  }
}

export default function AgentEnginesPanel({ server }: AgentEnginesPanelProps) {
  const [engines, setEngines] = useState<AgentEngineStatus[]>([]);
  const [keyOwner, setKeyOwner] = useState('');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const load = useCallback(async () => {
    try {
      const client = getClient(server);
      const resp = await client.listAgentEngines();
      setEngines(resp.engines);
      setKeyOwner(resp.keyOwner);
      setError('');
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to load agent engines');
    } finally {
      setLoading(false);
    }
  }, [server]);

  useEffect(() => {
    setLoading(true);
    load();
  }, [load]);

  if (loading) {
    return (
      <div className="flex items-center gap-2 p-6 text-[var(--text-muted)]">
        <Loader2 className="h-4 w-4 animate-spin" /> Loading agent engines…
      </div>
    );
  }

  return (
    <div className="p-4">
      <div className="mb-4 flex items-center justify-between">
        <div>
          <h2 className="text-lg font-semibold">Agents</h2>
          <p className="text-xs text-[var(--text-muted)]">
            Configured agent engines and whether each is ready to run a skill
            {keyOwner ? <> — key owner: <span className="font-mono">{keyOwner}</span></> : null}
          </p>
        </div>
        <button
          onClick={() => { setLoading(true); load(); }}
          className="flex items-center gap-1.5 rounded-lg border border-[var(--border-subtle)] bg-[var(--surface)] px-3 py-1.5 text-sm hover:bg-[var(--surface-2)]"
        >
          <RefreshCw className="h-3.5 w-3.5" /> Refresh
        </button>
      </div>

      {error && (
        <div className="mb-3 rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-[var(--c-red)]">{error}</div>
      )}

      {engines.some((e) => e.readiness === 'AGENT_ENGINE_READINESS_UNKNOWN_DIRECT_MODE') && (
        <div className="mb-3 rounded-lg border border-[var(--border-subtle)] bg-[var(--surface-2)] px-3 py-2 text-xs text-[var(--text-muted)]">
          This daemon serves no model gateway, so readiness is unknown here — each box&apos;s own secrets decide
          whether a skill can run.
        </div>
      )}

      <div className="overflow-hidden rounded-xl border border-[var(--border-subtle)]">
        <table className="w-full text-sm">
          <thead className="bg-[var(--surface-2)] text-left text-xs text-[var(--text-muted)]">
            <tr>
              <th className="px-4 py-2 font-medium">Engine</th>
              <th className="px-4 py-2 font-medium">Provider</th>
              <th className="px-4 py-2 font-medium">Readiness</th>
              <th className="px-4 py-2 font-medium">Credential source</th>
              <th className="px-4 py-2 font-medium">Default</th>
              <th className="px-4 py-2 font-medium">Skills using it</th>
              <th className="px-4 py-2 font-medium">Reason</th>
            </tr>
          </thead>
          <tbody>
            {engines.map((e) => (
              <tr key={e.engine} className="border-t border-[var(--border-subtle)]">
                <td className="px-4 py-2 font-medium">{ENGINE_LABELS[e.engine]}</td>
                <td className="px-4 py-2 text-[var(--text-muted)]">{PROVIDER_LABELS[e.provider]}</td>
                <td className="px-4 py-2">{readinessBadge(e.readiness)}</td>
                <td className="px-4 py-2 text-[var(--text-muted)]">{SOURCE_LABELS[e.source]}</td>
                <td className="px-4 py-2">{e.isDefault ? <CheckCircle2 className="h-3.5 w-3.5 text-[var(--c-emerald)]" /> : null}</td>
                <td className="px-4 py-2 text-[var(--text-muted)]">
                  {e.skillIds.length > 0 ? e.skillIds.join(', ') : '—'}
                </td>
                <td className="px-4 py-2 text-xs text-[var(--text-muted)]">{e.reason || '—'}</td>
              </tr>
            ))}
            {engines.length === 0 && (
              <tr><td colSpan={7} className="px-4 py-6 text-center text-[var(--text-muted)]">No agent engines configured.</td></tr>
            )}
          </tbody>
        </table>
      </div>

      <p className="mt-3 text-xs text-[var(--text-muted)]">
        This page is read-only. Keys are set with{' '}
        <code className="rounded bg-[var(--surface-2)] px-1 py-0.5">containarium gateway key set</code> — see{' '}
        <a href={GATEWAY_KEY_DOC_URL} target="_blank" rel="noreferrer" className="underline hover:text-[var(--text-primary)]">
          the model gateway doc
        </a>.
      </p>
    </div>
  );
}
