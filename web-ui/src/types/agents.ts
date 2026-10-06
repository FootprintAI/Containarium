import { z } from 'zod';

// #2224: the ListAgentEngines response is parsed with zod, not cast — a
// `body as ListAgentEnginesResponse` would compile fine against whatever
// shape the daemon happens to send, which is exactly the untyped-boundary
// anti-pattern CLAUDE.md calls out. Enum fields and arrays default to the
// proto3 zero value because protojson (the daemon's JSON encoding) omits a
// field entirely when it equals that zero value — a real response can and
// does arrive missing `reason`, `skillIds`, `isDefault`.
//
// Each enum's raw values are exported separately (AgentEngineValues, etc.)
// so swagger-contract.test.ts can diff them against the generated swagger
// directly, without reaching into zod's internals.

export const AgentEngineValues = [
  'AGENT_ENGINE_UNSPECIFIED',
  'AGENT_ENGINE_CLAUDE',
  'AGENT_ENGINE_CODEX',
  'AGENT_ENGINE_GEMINI',
] as const;
export const AgentEngineSchema = z.enum(AgentEngineValues).default('AGENT_ENGINE_UNSPECIFIED');
export type AgentEngine = z.infer<typeof AgentEngineSchema>;

export const AgentEngineReadinessValues = [
  'AGENT_ENGINE_READINESS_UNSPECIFIED',
  'AGENT_ENGINE_READINESS_READY',
  'AGENT_ENGINE_READINESS_NOT_READY',
  'AGENT_ENGINE_READINESS_UNKNOWN_DIRECT_MODE',
] as const;
export const AgentEngineReadinessSchema = z.enum(AgentEngineReadinessValues).default('AGENT_ENGINE_READINESS_UNSPECIFIED');
export type AgentEngineReadiness = z.infer<typeof AgentEngineReadinessSchema>;

export const AgentCredentialSourceValues = [
  'AGENT_CREDENTIAL_SOURCE_UNSPECIFIED',
  'AGENT_CREDENTIAL_SOURCE_GLOBAL_KEY',
  'AGENT_CREDENTIAL_SOURCE_OWNER_KEY',
  'AGENT_CREDENTIAL_SOURCE_DIRECT_MODE',
] as const;
export const AgentCredentialSourceSchema = z.enum(AgentCredentialSourceValues).default('AGENT_CREDENTIAL_SOURCE_UNSPECIFIED');
export type AgentCredentialSource = z.infer<typeof AgentCredentialSourceSchema>;

export const GatewayProviderValues = [
  'GATEWAY_PROVIDER_UNSPECIFIED',
  'GATEWAY_PROVIDER_ANTHROPIC',
  'GATEWAY_PROVIDER_OPENAI',
  'GATEWAY_PROVIDER_GEMINI',
  'GATEWAY_PROVIDER_GEMINI_OPENAI',
  'GATEWAY_PROVIDER_KAFEIDO',
] as const;
export const GatewayProviderSchema = z.enum(GatewayProviderValues).default('GATEWAY_PROVIDER_UNSPECIFIED');
export type GatewayProvider = z.infer<typeof GatewayProviderSchema>;

export const AgentEngineStatusSchema = z.object({
  engine: AgentEngineSchema,
  provider: GatewayProviderSchema,
  readiness: AgentEngineReadinessSchema,
  reason: z.string().default(''),
  source: AgentCredentialSourceSchema,
  isDefault: z.boolean().default(false),
  skillIds: z.array(z.string()).default([]),
});
export type AgentEngineStatus = z.infer<typeof AgentEngineStatusSchema>;

// AGENT_ENGINE_STATUS_KEYS pins the exact wire keys this schema expects, so
// swagger-contract.test.ts can diff them against the generated swagger's
// AgentEngineStatus property names.
export const AgentEngineStatusKeys = ['engine', 'provider', 'readiness', 'reason', 'source', 'isDefault', 'skillIds'] as const;

export const ListAgentEnginesResponseSchema = z.object({
  engines: z.array(AgentEngineStatusSchema).default([]),
  keyOwner: z.string().default(''),
});
export type ListAgentEnginesResponse = z.infer<typeof ListAgentEnginesResponseSchema>;
