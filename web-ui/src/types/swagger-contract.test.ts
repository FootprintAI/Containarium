import { describe, it, expect } from 'vitest';
import { readFileSync } from 'fs';
import { resolve } from 'path';
import {
  AgentEngineValues,
  AgentEngineReadinessValues,
  AgentCredentialSourceValues,
  GatewayProviderValues,
  AgentEngineStatusKeys,
} from './agents';

// #2224: this is the typed-boundary check in place of a generated TS client
// — web-ui's types are hand-written (a repo-wide, pre-existing condition,
// not fixed by this PR), so THIS test is what makes proto drift fail a test
// instead of silently decoding wrong. It reads the real generated swagger
// (api/swagger/containarium.swagger.json, produced by `make proto`) and
// diffs it against the zod schema's own enum values and object keys.
//
// Per project convention, this test must be proven to actually fail once:
// renaming a key in src/types/agents.ts (e.g. `isDefault` -> `default`) or
// dropping an enum value must turn this red. Confirmed locally before this
// PR shipped (see the PR description) — not re-verified on every CI run,
// since that would mean breaking the schema on purpose every time.

const swaggerPath = resolve(__dirname, '../../../api/swagger/containarium.swagger.json');

interface SwaggerDefinition {
  enum?: string[];
  properties?: Record<string, unknown>;
}

interface SwaggerDoc {
  definitions?: Record<string, SwaggerDefinition>;
  paths?: Record<string, { get?: { responses: Record<string, { schema?: { $ref?: string } }> } }>;
}

function loadDoc(): SwaggerDoc {
  return JSON.parse(readFileSync(swaggerPath, 'utf-8'));
}

function loadDefinition(name: string): SwaggerDefinition {
  const def = loadDoc().definitions?.[name];
  if (!def) {
    throw new Error(`swagger definition ${name} not found at ${swaggerPath} — did ListAgentEngines move or get renamed?`);
  }
  return def;
}

describe('swagger contract: agent-router types', () => {
  it('ListAgentEngines is still exposed at GET /v1/agent-engines', () => {
    const doc = loadDoc();
    const path = doc.paths?.['/v1/agent-engines'];
    expect(path).toBeDefined();
    expect(path?.get).toBeDefined();
    expect(path?.get?.responses['200'].schema?.$ref).toBe('#/definitions/ListAgentEnginesResponse');
  });

  it('AgentEngine enum values match the schema exactly', () => {
    const def = loadDefinition('AgentEngine');
    expect(def.enum).toEqual([...AgentEngineValues]);
  });

  it('AgentEngineReadiness enum values match the schema exactly', () => {
    const def = loadDefinition('AgentEngineReadiness');
    expect(def.enum).toEqual([...AgentEngineReadinessValues]);
  });

  it('AgentCredentialSource enum values match the schema exactly', () => {
    const def = loadDefinition('AgentCredentialSource');
    expect(def.enum).toEqual([...AgentCredentialSourceValues]);
  });

  it('GatewayProvider enum values match the schema exactly', () => {
    const def = loadDefinition('GatewayProvider');
    expect(def.enum).toEqual([...GatewayProviderValues]);
  });

  it('AgentEngineStatus property names match the schema exactly', () => {
    const def = loadDefinition('AgentEngineStatus');
    const swaggerKeys = Object.keys(def.properties ?? {}).sort();
    const schemaKeys = [...AgentEngineStatusKeys].sort();
    expect(swaggerKeys).toEqual(schemaKeys);
  });

  it('ListAgentEnginesResponse property names match the schema exactly', () => {
    const def = loadDefinition('ListAgentEnginesResponse');
    const swaggerKeys = Object.keys(def.properties ?? {}).sort();
    expect(swaggerKeys).toEqual(['engines', 'keyOwner']);
  });
});
