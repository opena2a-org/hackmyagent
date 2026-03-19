#!/usr/bin/env npx tsx
/**
 * verify-taxonomy-sync.ts
 *
 * Verifies that HMA's taxonomy.ts attack class mappings stay in sync with
 * the OpenA2A Registry's attack_classes table (seed script + SQL migrations).
 *
 * Parses both sources statically (no database connection required) and reports:
 *   - Attack classes in HMA but NOT in registry
 *   - Attack classes in registry but NOT in HMA
 *   - Attack classes present in both (in sync)
 *
 * Exit code 0 = in sync, 1 = out of sync.
 *
 * Usage:
 *   npx tsx scripts/verify-taxonomy-sync.ts
 *   npx ts-node scripts/verify-taxonomy-sync.ts
 */

import * as fs from 'fs';
import * as path from 'path';

// ---------------------------------------------------------------------------
// Configuration: file paths (relative to this script's location)
// ---------------------------------------------------------------------------

const HMA_ROOT = path.resolve(__dirname, '..');
const REGISTRY_ROOT = path.resolve(HMA_ROOT, '..', 'opena2a-registry');

const TAXONOMY_TS = path.join(HMA_ROOT, 'src', 'hardening', 'taxonomy.ts');
const SEED_SCRIPT = path.join(REGISTRY_ROOT, 'scripts', 'quality', 'seed-attack-taxonomy.mjs');
const MIGRATIONS_DIR = path.join(REGISTRY_ROOT, 'migrations');

// ---------------------------------------------------------------------------
// Parse HMA taxonomy.ts — extract unique attack class values (right side)
// ---------------------------------------------------------------------------

function parseHmaTaxonomy(filePath: string): Set<string> {
  const content = fs.readFileSync(filePath, 'utf-8');
  const classes = new Set<string>();

  // Match lines like:  'CHECK-ID': 'ATTACK-CLASS',
  const linePattern = /^\s*'[^']+'\s*:\s*'([^']+)'\s*,?\s*$/gm;
  let match: RegExpExecArray | null;
  while ((match = linePattern.exec(content)) !== null) {
    classes.add(match[1]);
  }

  return classes;
}

// ---------------------------------------------------------------------------
// Parse registry seed script — extract identifier values from ATTACK_CLASSES
// ---------------------------------------------------------------------------

function parseSeedScript(filePath: string): Set<string> {
  const content = fs.readFileSync(filePath, 'utf-8');
  const classes = new Set<string>();

  // Match lines like:  identifier: 'SOUL-POISON',
  const idPattern = /identifier:\s*'([^']+)'/g;
  let match: RegExpExecArray | null;
  while ((match = idPattern.exec(content)) !== null) {
    classes.add(match[1]);
  }

  return classes;
}

// ---------------------------------------------------------------------------
// Parse SQL migration files — extract identifiers from INSERT statements
// ---------------------------------------------------------------------------

function parseMigrations(migrationsDir: string): Set<string> {
  const classes = new Set<string>();

  if (!fs.existsSync(migrationsDir)) {
    return classes;
  }

  const files = fs.readdirSync(migrationsDir)
    .filter(f => f.endsWith('.sql'))
    .sort();

  for (const file of files) {
    const content = fs.readFileSync(path.join(migrationsDir, file), 'utf-8');

    // Only look at files that INSERT INTO attack_classes
    if (!content.includes('attack_classes')) continue;

    // Match INSERT values where identifier is first text value:
    //   'NEMO-CRED-LEAK',
    // after the opening VALUES (
    // Pattern: first quoted string after VALUES (
    const insertBlocks = content.split(/INSERT\s+INTO\s+attack_classes\s*\(/i);
    for (let i = 1; i < insertBlocks.length; i++) {
      const block = insertBlocks[i];
      // Find the VALUES clause, then the first quoted string
      const valuesMatch = block.match(/VALUES\s*\(\s*'([^']+)'/i);
      if (valuesMatch) {
        classes.add(valuesMatch[1]);
      }
    }
  }

  return classes;
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

function main(): void {
  console.log('Taxonomy Sync Verification');
  console.log('='.repeat(60));

  // Validate paths exist
  if (!fs.existsSync(TAXONOMY_TS)) {
    console.error(`ERROR: HMA taxonomy file not found: ${TAXONOMY_TS}`);
    process.exit(2);
  }

  // Parse HMA
  const hmaClasses = parseHmaTaxonomy(TAXONOMY_TS);
  console.log(`\nHMA taxonomy.ts: ${hmaClasses.size} unique attack classes`);

  // Parse registry (seed script + migrations)
  const registryClasses = new Set<string>();

  if (fs.existsSync(SEED_SCRIPT)) {
    const seedClasses = parseSeedScript(SEED_SCRIPT);
    console.log(`Registry seed script: ${seedClasses.size} attack classes`);
    for (const c of seedClasses) registryClasses.add(c);
  } else {
    console.log(`Registry seed script not found: ${SEED_SCRIPT} (skipped)`);
  }

  const migrationClasses = parseMigrations(MIGRATIONS_DIR);
  if (migrationClasses.size > 0) {
    console.log(`Registry migrations: ${migrationClasses.size} attack classes`);
    for (const c of migrationClasses) registryClasses.add(c);
  } else {
    console.log(`Registry migrations directory: no attack class inserts found`);
  }

  console.log(`Registry total (deduplicated): ${registryClasses.size} attack classes`);

  // Compute diffs
  const hmaOnly = new Set<string>();
  const registryOnly = new Set<string>();
  const inSync = new Set<string>();

  for (const c of hmaClasses) {
    if (registryClasses.has(c)) {
      inSync.add(c);
    } else {
      hmaOnly.add(c);
    }
  }

  for (const c of registryClasses) {
    if (!hmaClasses.has(c)) {
      registryOnly.add(c);
    }
  }

  // Report
  console.log('\n' + '='.repeat(60));
  console.log('RESULTS');
  console.log('='.repeat(60));

  console.log(`\nIn sync: ${inSync.size} attack classes`);
  if (inSync.size > 0) {
    const sorted = [...inSync].sort();
    for (const c of sorted) {
      console.log(`  [OK] ${c}`);
    }
  }

  console.log(`\nIn HMA but NOT in registry: ${hmaOnly.size}`);
  if (hmaOnly.size > 0) {
    console.log('  (These need to be added to the registry via migration or seed script)');
    const sorted = [...hmaOnly].sort();
    for (const c of sorted) {
      console.log(`  [MISSING IN REGISTRY] ${c}`);
    }
  }

  console.log(`\nIn registry but NOT in HMA: ${registryOnly.size}`);
  if (registryOnly.size > 0) {
    console.log('  (Potential coverage gaps -- HMA may need new checks for these)');
    const sorted = [...registryOnly].sort();
    for (const c of sorted) {
      console.log(`  [MISSING IN HMA] ${c}`);
    }
  }

  // Verdict
  const outOfSync = hmaOnly.size > 0 || registryOnly.size > 0;
  console.log('\n' + '='.repeat(60));
  if (outOfSync) {
    console.log('VERDICT: OUT OF SYNC');
    console.log(`  ${hmaOnly.size} classes need registry migration`);
    console.log(`  ${registryOnly.size} classes have no HMA coverage`);
    process.exit(1);
  } else {
    console.log('VERDICT: IN SYNC');
    console.log(`  All ${inSync.size} attack classes are present in both HMA and registry.`);
    process.exit(0);
  }
}

main();
