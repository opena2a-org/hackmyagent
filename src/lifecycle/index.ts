/**
 * Context Lifecycle Scanner
 *
 * Models how agent context evolves through stages of execution:
 * - Stage 0: Static artifact scan (current HMA hardening checks)
 * - Stage 1: System prompt assembly simulation
 * - Stage 2: Runtime behavior monitoring (future, via ARP)
 */

export { scanAssembly, toLifecycleResult } from './assembly-scanner';
export type {
  LifecycleStage,
  LifecycleScanResult,
  AssemblyComponent,
  AssemblyInteraction,
} from '../hardening/security-check';
