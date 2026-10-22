import { describe, it, expect } from 'vitest';
import { ListAgentEnginesResponseSchema } from './agents';

// #2224: this boundary is parsed, never cast — a `body as ListAgentEnginesResponse`
// would compile fine against a daemon response shaped however the server
// happens to send it; zod is what actually checks the wire contract.
describe('ListAgentEnginesResponseSchema', () => {
  it('parses a full, real-shaped response', () => {
    const body = {
      keyOwner: 'user:alice',
      engines: [
        {
          engine: 'AGENT_ENGINE_CLAUDE',
          provider: 'GATEWAY_PROVIDER_ANTHROPIC',
          readiness: 'AGENT_ENGINE_READINESS_READY',
          source: 'AGENT_CREDENTIAL_SOURCE_GLOBAL_KEY',
          isDefault: true,
          skillIds: ['hello-agent'],
        },
        {
          engine: 'AGENT_ENGINE_CODEX',
          provider: 'GATEWAY_PROVIDER_OPENAI',
          readiness: 'AGENT_ENGINE_READINESS_NOT_READY',
          reason: 'no key for provider openai; fix: containarium gateway key set user:alice --provider openai --key <value>',
        },
      ],
    };
    const parsed = ListAgentEnginesResponseSchema.parse(body);
    expect(parsed.keyOwner).toBe('user:alice');
    expect(parsed.engines).toHaveLength(2);
    expect(parsed.engines[0].isDefault).toBe(true);
    expect(parsed.engines[0].skillIds).toEqual(['hello-agent']);
    expect(parsed.engines[1].readiness).toBe('AGENT_ENGINE_READINESS_NOT_READY');
  });

  it('fills in protojson-omitted zero-value fields with their proto defaults', () => {
    // protojson omits a field entirely when it equals the proto3 zero value
    // (an UNSPECIFIED enum, "", false, []) — a real wire response can look
    // like this for e.g. a row whose reason is empty or skillIds is empty.
    const parsed = ListAgentEnginesResponseSchema.parse({
      engines: [{ engine: 'AGENT_ENGINE_GEMINI' }],
    });
    expect(parsed.keyOwner).toBe('');
    expect(parsed.engines[0].reason).toBe('');
    expect(parsed.engines[0].isDefault).toBe(false);
    expect(parsed.engines[0].skillIds).toEqual([]);
    expect(parsed.engines[0].readiness).toBe('AGENT_ENGINE_READINESS_UNSPECIFIED');
    expect(parsed.engines[0].source).toBe('AGENT_CREDENTIAL_SOURCE_UNSPECIFIED');
  });

  it('rejects an unknown enum value rather than silently accepting it', () => {
    expect(() =>
      ListAgentEnginesResponseSchema.parse({
        engines: [{ engine: 'AGENT_ENGINE_SOME_FUTURE_VALUE' }],
      })
    ).toThrow();
  });

  it('rejects a response missing the engines array entirely only if not an object', () => {
    // An empty object is a legitimate "no engines" shape (shouldn't happen in
    // practice, but the schema must not throw on it) — only a non-object body
    // should fail.
    expect(() => ListAgentEnginesResponseSchema.parse({})).not.toThrow();
    expect(() => ListAgentEnginesResponseSchema.parse('not an object')).toThrow();
  });
});
