import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
  normalizeEndpoint,
  isLoopbackEndpoint,
  PLAINTEXT_OPT_IN_KEY,
  resetPlaintextWarnings,
} from './client';

describe('normalizeEndpoint plaintext fallback (#3517)', () => {
  let warn: ReturnType<typeof vi.spyOn>;
  beforeEach(() => {
    resetPlaintextWarnings();
    localStorage.removeItem(PLAINTEXT_OPT_IN_KEY);
    warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
  });
  afterEach(() => warn.mockRestore());

  it('still falls back to http:// and warns for a scheme-less non-loopback endpoint', () => {
    expect(normalizeEndpoint('203.0.113.7:8080')).toBe('http://203.0.113.7:8080');
    expect(warn).toHaveBeenCalledTimes(1);
    expect(String(warn.mock.calls[0][0])).toContain('plaintext');
  });

  it('warns once per endpoint, not once per request', () => {
    normalizeEndpoint('203.0.113.7:8080');
    normalizeEndpoint('203.0.113.7:8080');
    expect(warn).toHaveBeenCalledTimes(1);
  });

  it('is silent when the operator opted in', () => {
    localStorage.setItem(PLAINTEXT_OPT_IN_KEY, '1');
    expect(normalizeEndpoint('203.0.113.7:8080')).toBe('http://203.0.113.7:8080');
    expect(warn).not.toHaveBeenCalled();
  });

  it.each(['localhost:8080', '127.0.0.1:8080', '[::1]:8080', 'https://example.com', 'http://203.0.113.7:8080'])(
    'does not warn for %s',
    (ep) => {
      normalizeEndpoint(ep);
      expect(warn).not.toHaveBeenCalled();
    },
  );

  it('isLoopbackEndpoint rejects lookalikes', () => {
    expect(isLoopbackEndpoint('localhost.example.com:80')).toBe(false);
    expect(isLoopbackEndpoint('localhost:80')).toBe(true);
  });
});
