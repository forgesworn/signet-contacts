import { describe, it, expect } from 'vitest';
import { WIRE_VERSION } from './version.js';

describe('package scaffold', () => {
  it('exports the wire version', () => {
    expect(WIRE_VERSION).toBe(2);
  });
});
