import { describe, it, expect } from 'vitest';
import { SoulScanner } from '../../src/soul/scanner.js';

describe('detectProfile: orchestrator delegate patterns', () => {
  const scanner = new SoulScanner();

  it('detects delegate ... agent on one line', () => {
    expect(scanner.detectProfile('The planner may delegate research to a second agent.')).toBe('orchestrator');
  });

  it('detects agent ... delegate on one line', () => {
    expect(scanner.detectProfile('Each agent may delegate subtasks.')).toBe('orchestrator');
  });

  it('does not match delegate and agent on separate lines', () => {
    expect(scanner.detectProfile('We delegate nothing.\nThe agent stays put.')).not.toBe('orchestrator');
  });
});
