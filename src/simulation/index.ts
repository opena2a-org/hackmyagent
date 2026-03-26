/**
 * HMA Skill Simulation Engine
 *
 * Behavioral simulation that observes what skills actually DO.
 * Three layers: NanoMind semantic (8ms) -> targeted probes (3s) -> full simulation (30s).
 * Target: < 1% false positive rate vs industry 0.12% scanner agreement (theweatherreport.ai).
 */

export { SimulationEngine, parseSkillProfile } from './engine.js';
export { MockToolEnvironment } from './mock-tools.js';
export { detectBestBackend, NanoMindBackend, AnthropicBackend, OllamaBackend, executeProbeLLM } from './llm-executor.js';
export type { LLMBackend } from './llm-executor.js';
export { ALL_PROBES, LAYER2_PROBES, LAYER3_PROBES, getProbesByCategory, getProbeCategoryCounts } from './probes.js';
export type {
  SimulationResult,
  SimulationVerdict,
  SimulationConfig,
  ProbeDefinition,
  ProbeResult,
  ProbeCategory,
  SkillProfile,
  MockToolCall,
  MockToolType,
  MockToolConfig,
} from './types.js';
export { DEFAULT_LAYER2_CONFIG, DEFAULT_LAYER3_CONFIG } from './types.js';
