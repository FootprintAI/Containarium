import '@testing-library/jest-dom/vitest';
import { afterEach } from 'vitest';
import { cleanup } from '@testing-library/react';

// testing-library's auto-cleanup only self-registers when it detects a
// global `afterEach` (vitest's `test.globals` is off here, so it doesn't) —
// without this, each test's render() accumulates in the same jsdom document.
afterEach(cleanup);
