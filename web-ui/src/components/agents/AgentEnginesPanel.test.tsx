import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import AgentEnginesPanel from './AgentEnginesPanel';
import { Server } from '@/src/types/server';

const listAgentEngines = vi.fn();

vi.mock('@/src/lib/api/client', () => ({
  getClient: () => ({ listAgentEngines }),
}));

const server: Server = { id: 's1', name: 'test', endpoint: 'https://example.test', token: 'tok', addedAt: Date.now() };

describe('AgentEnginesPanel', () => {
  beforeEach(() => {
    listAgentEngines.mockReset();
  });

  it('renders each engine with its readiness, source, and skills', async () => {
    listAgentEngines.mockResolvedValue({
      keyOwner: 'user:alice',
      engines: [
        {
          engine: 'AGENT_ENGINE_CLAUDE',
          provider: 'GATEWAY_PROVIDER_ANTHROPIC',
          readiness: 'AGENT_ENGINE_READINESS_READY',
          reason: '',
          source: 'AGENT_CREDENTIAL_SOURCE_GLOBAL_KEY',
          isDefault: true,
          skillIds: ['hello-agent'],
        },
        {
          engine: 'AGENT_ENGINE_CODEX',
          provider: 'GATEWAY_PROVIDER_OPENAI',
          readiness: 'AGENT_ENGINE_READINESS_NOT_READY',
          reason: 'no key for provider openai',
          source: 'AGENT_CREDENTIAL_SOURCE_UNSPECIFIED',
          isDefault: false,
          skillIds: [],
        },
      ],
    });

    render(<AgentEnginesPanel server={server} />);

    await waitFor(() => expect(screen.getByText('Claude')).toBeInTheDocument());
    expect(screen.getByText('Codex')).toBeInTheDocument();
    expect(screen.getByText('ready')).toBeInTheDocument();
    expect(screen.getByText('not ready')).toBeInTheDocument();
    expect(screen.getByText('hello-agent')).toBeInTheDocument();
    expect(screen.getByText('no key for provider openai')).toBeInTheDocument();
    expect(screen.getByText(/user:alice/)).toBeInTheDocument();
    expect(screen.getByText('anthropic')).toBeInTheDocument();
    expect(screen.getByText('openai')).toBeInTheDocument();
  });

  it('shows an empty state when no engines are configured', async () => {
    listAgentEngines.mockResolvedValue({ keyOwner: '', engines: [] });

    render(<AgentEnginesPanel server={server} />);

    await waitFor(() => expect(screen.getByText('No agent engines configured.')).toBeInTheDocument());
  });

  it('surfaces a load error', async () => {
    listAgentEngines.mockRejectedValue(new Error('daemon unreachable'));

    render(<AgentEnginesPanel server={server} />);

    await waitFor(() => expect(screen.getByText('daemon unreachable')).toBeInTheDocument());
  });

  it('shows every engine as not ready with a doc link when no keys are set (no blank page)', async () => {
    listAgentEngines.mockResolvedValue({
      keyOwner: 'user:alice',
      engines: [
        { engine: 'AGENT_ENGINE_CLAUDE', provider: 'GATEWAY_PROVIDER_ANTHROPIC', readiness: 'AGENT_ENGINE_READINESS_NOT_READY', reason: 'no key for provider anthropic', source: 'AGENT_CREDENTIAL_SOURCE_UNSPECIFIED', isDefault: false, skillIds: [] },
        { engine: 'AGENT_ENGINE_CODEX', provider: 'GATEWAY_PROVIDER_OPENAI', readiness: 'AGENT_ENGINE_READINESS_NOT_READY', reason: 'no key for provider openai', source: 'AGENT_CREDENTIAL_SOURCE_UNSPECIFIED', isDefault: false, skillIds: [] },
        { engine: 'AGENT_ENGINE_GEMINI', provider: 'GATEWAY_PROVIDER_GEMINI', readiness: 'AGENT_ENGINE_READINESS_NOT_READY', reason: 'no key for provider gemini', source: 'AGENT_CREDENTIAL_SOURCE_UNSPECIFIED', isDefault: false, skillIds: [] },
      ],
    });

    render(<AgentEnginesPanel server={server} />);

    await waitFor(() => expect(screen.getAllByText('not ready')).toHaveLength(3));
    expect(screen.getByText('the model gateway doc')).toBeInTheDocument();
  });

  it('shows the direct-mode note when readiness is unknown', async () => {
    listAgentEngines.mockResolvedValue({
      keyOwner: '',
      engines: [
        { engine: 'AGENT_ENGINE_CLAUDE', provider: 'GATEWAY_PROVIDER_ANTHROPIC', readiness: 'AGENT_ENGINE_READINESS_UNKNOWN_DIRECT_MODE', reason: 'daemon serves no model gateway; the box’s own secrets decide', source: 'AGENT_CREDENTIAL_SOURCE_DIRECT_MODE', isDefault: false, skillIds: [] },
      ],
    });

    render(<AgentEnginesPanel server={server} />);

    await waitFor(() => expect(screen.getByText('unknown (direct mode)')).toBeInTheDocument());
    expect(screen.getByText(/serves no model gateway, so readiness is unknown here/)).toBeInTheDocument();
  });
});
