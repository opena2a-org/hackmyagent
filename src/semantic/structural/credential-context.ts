/**
 * Context-Aware Credential Detection (Layer 2)
 *
 * Catches credentials that regex misses by understanding structure:
 * - URL passwords (postgres://admin:password123@host)
 * - Generic tokens in config (key-name heuristics)
 * - Short API keys below regex thresholds
 * - Secrets in instruction files (CLAUDE.md, .cursorrules)
 */

import type { SemanticFinding, AnalysisFile } from '../types';
import type { GitContext } from './git-context';
import { isVisualFiller } from '../../types/credential-format.js';

/**
 * How much of a value must survive the drawn runs, for the call sites that
 * apply no length floor of their own (the MCP env block, the URL password).
 *
 * Small on purpose. The SEM-CRED-002 shapes carry an 8-character floor for
 * their own reasons, and reusing it here would turn a blank gate into a length
 * gate: it silently dropped `supersecretpassword` and `hunt3r` from MCP env
 * blocks the first time, and `hunter2` is a real URL password. A gate added to
 * suppress drawn blanks must suppress drawn blanks and nothing else.
 */
const MIN_DRAWN_ONLY_CORE_CHARS = 2;

/** Key names that indicate a secret value */
const SECRET_KEY_PATTERN =
  /^(.*_)?(secret|token|key|password|passwd|credential|auth|apikey|api_key|access_key|private_key|client_secret|signing_key|encryption_key|master_key|jwt_secret|session_secret|db_password|database_password)(_.*)?$/i;

/** URL with embedded credentials: protocol://user:password@host
 * Uses greedy .+ for password to handle @ chars in passwords.
 * The greedy match backtracks to the last valid @hostname boundary. */
const URL_CREDENTIAL_PATTERN =
  /(?:postgres|postgresql|mysql|mongodb|redis|amqp|rabbitmq|ftp|sftp|https?):\/\/([^:]+):(.+)@([a-zA-Z0-9][-a-zA-Z0-9.]*(?::\d+)?(?:\/[^\s"',)]*)?)/gi;

/**
 * Classify a secret by its key name and value.
 * Returns { type, masked } where type is a human-readable label and
 * masked shows the first 5 chars of the value followed by ****.
 */
function classifySecret(key: string, value: string): { type: string; masked: string } {
  const v = value.trim().replace(/^["']|["']$/g, '');
  const preview = v.length > 5 ? v.slice(0, 5) + '****' : '****';

  // Value-based classification (most reliable)
  if (/^sk-ant-/.test(v)) return { type: 'Anthropic API key', masked: preview };
  if (/^sk-proj-/.test(v) || /^sk-[a-zA-Z0-9]{48,}/.test(v)) return { type: 'OpenAI API key', masked: preview };
  if (/^AKIA[0-9A-Z]{16}/.test(v)) return { type: 'AWS access key', masked: preview };
  if (/^(ghp_|ghs_|gho_|github_pat_)/.test(v)) return { type: 'GitHub token', masked: preview };
  if (/^AIza[0-9A-Za-z_-]{35}/.test(v)) return { type: 'Google API key', masked: preview };
  if (/^xoxb-/.test(v) || /^xoxa-/.test(v)) return { type: 'Slack token', masked: preview };

  // Key-name fallback
  const k = key.toLowerCase();
  if (/openai|gpt/.test(k)) return { type: 'OpenAI API key', masked: preview };
  if (/anthropic|claude/.test(k)) return { type: 'Anthropic API key', masked: preview };
  if (/aws|amazon/.test(k) && /key|secret/.test(k)) return { type: 'AWS credential', masked: preview };
  if (/github/.test(k)) return { type: 'GitHub token', masked: preview };
  if (/google|gcp/.test(k)) return { type: 'Google API key', masked: preview };
  if (/stripe/.test(k)) return { type: 'Stripe key', masked: preview };
  if (/twilio/.test(k)) return { type: 'Twilio credential', masked: preview };
  if (/sendgrid/.test(k)) return { type: 'SendGrid key', masked: preview };
  if (/slack/.test(k)) return { type: 'Slack token', masked: preview };
  if (/jwt|session/.test(k)) return { type: 'JWT/session secret', masked: preview };
  if (/password|passwd|pwd/.test(k)) return { type: 'password', masked: preview };
  if (/private.*key|signing.*key/.test(k)) return { type: 'private key', masked: preview };

  return { type: 'secret', masked: preview };
}

/**
 * Value-level gate shared by all three SEM-CRED-002 shapes (JSON pair, YAML
 * pair, `KEY=VALUE`).
 *
 * Hoisted into one function on purpose. Three of the four call sites carried
 * byte-identical copies of the length/all-letters test, and the entropy floor
 * that fixed AST-CRED-003 was added to neither — so the reported complaint kept
 * reproducing through this detector: a `CLAUDE.md` onboarding checklist reading
 * `password: ______…` scored SEM-CRED-002 CRITICAL, on the same 47-underscore
 * form blank. Two of the three copies drifting is how that gap opened; one
 * function is what keeps it closed.
 *
 * The filler test is `isVisualFiller`, NOT the AST path's
 * `isCredibleEntropyBlob`. Both reject the reported form blank, but they are
 * asked different questions. The AST fallback judges an ANONYMOUS 40+ character
 * run found anywhere in a document, where structure is the only evidence and a
 * run of one repeated symbol is filler. Here a key name has already said "this
 * is a secret", and the structural rules are far too blunt for an 8-character
 * value: they dropped `Ab12Ab12Ab12…` (period 4) and the base64 of an all-zero
 * AES key (`'A'x43`), both weak but entirely real secrets. Keying on the filler
 * CHARACTERS separates the classes exactly at this size.
 */
function looksLikeSecretValue(value: string): boolean {
  if (value.length < 8) return false;
  // All-letters values are words, not secrets.
  if (/^[a-z]+$/i.test(value)) return false;
  // A drawn blank (`____…`, `----`, `....`) is not a value.
  if (isVisualFiller(value)) return false;
  return true;
}

/** Values that are NOT secrets (env var refs, booleans, paths, etc.) */
function isNonSecretValue(value: string): boolean {
  const trimmed = value.trim().replace(/^["']|["']$/g, '');

  // Empty or whitespace
  if (!trimmed || trimmed.length === 0) return true;

  // Env var reference
  if (/^\$\{.*\}$/.test(trimmed) || /^\$[A-Z_]+$/.test(trimmed)) return true;

  // Boolean
  if (/^(true|false)$/i.test(trimmed)) return true;

  // Pure number
  if (/^\d+(\.\d+)?$/.test(trimmed)) return true;

  // File path (starts with / or ./ or ~/)
  if (/^[.~]?\//.test(trimmed) && !trimmed.includes('@')) return true;

  // URL without credentials
  if (/^https?:\/\/[^:@]*$/.test(trimmed)) return true;

  // Placeholder values.
  //
  // NOTE: prefix-anchored, so this also matches any value merely BEGINNING
  // with the vocabulary — `examplePassw0rd!` reads as documentation. That is a
  // real weakness, but it is bounded here: every caller of this function pairs
  // it with a key that already had to match SECRET_KEY_PATTERN, so the key
  // carries the signal and the value is only ever a veto.
  //
  // Anchoring it at both ends was tried and reverted. It closes the bypass and
  // strictly narrows suppression — but on this function's real call sites it
  // un-suppresses the redaction forms that dominate committed templates
  // (`xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`, `example-api-key-12345`,
  // `TODO: add key`), each of which becomes a CRITICAL SEM-CRED-004 in an MCP
  // config. Measured 48 new false-positive rows against 16 intended gains.
  //
  // Fixing it properly needs entropy corroboration rather than vocabulary
  // alone, plus a corpus re-bake. Tracked separately; do NOT hand a bare,
  // key-less value to this function in the meantime — see
  // `isPlaceholderUrlPassword` for what a caller without a key should use.
  if (/^(xxx|your[-_]|change[-_]me|replace[-_]|TODO|FIXME|placeholder|example)/i.test(trimmed)) return true;

  // Angle-bracket templates: <APIKEY>, <your_token>, <TENANT_NAME>
  if (/^<[^>]+>$/.test(trimmed)) return true;

  // Common non-secret config values
  if (/^(localhost|127\.0\.0\.1|0\.0\.0\.0|none|null|undefined|default)$/i.test(trimmed)) return true;

  return false;
}

/** Severity based on file location */
function severityForFile(filePath: string): 'critical' | 'high' {
  const lower = filePath.toLowerCase();

  // In LLM context window — exposed to AI provider, extractable via prompt injection
  if (
    lower.endsWith('claude.md') ||
    lower.endsWith('.cursorrules') ||
    lower.endsWith('.windsurfrules') ||
    lower.endsWith('.clinerules') ||
    lower.includes('copilot-instructions')
  ) {
    return 'critical';
  }

  // MCP configs — tool config, often committed
  if (
    lower.includes('mcp.json') ||
    lower.includes('mcp.yaml')
  ) {
    return 'critical';
  }

  // .env files that might be committed
  if (lower.includes('.env')) {
    return 'high';
  }

  // Config files
  return 'high';
}

/**
 * #208 .env-specific severity that consults git tracking state.
 *
 * Only downgrades when the file is .env-like AND the gitContext can prove
 * the credential is not in version control (not tracked, not in
 * history reachable from --all + --reflog). All other paths keep HIGH so
 * we do not weaken detection on credentials that ARE leaked.
 *
 * Order MUST be: index, then history, then ignored. A tracked file can
 * match a gitignore pattern; downgrading on `isGitignored` alone would
 * miss real leaks.
 *
 * Symlink defense: if the .env candidate is a symlink, the resolved
 * target is checked too. A symlink to a tracked file stays HIGH.
 *
 * Returns the unchanged base severity for non-.env files (e.g. CLAUDE.md
 * stays CRITICAL; MCP configs stay CRITICAL; generic config.json stays
 * HIGH).
 */
function effectiveSeverityForEnvCredential(
  filePath: string,
  gitContext?: GitContext,
): 'critical' | 'high' | 'medium' {
  const base = severityForFile(filePath);
  if (base === 'critical') return 'critical';

  const lower = filePath.toLowerCase();
  if (!lower.includes('.env')) return base;

  // No git context (or not a git repo) -> can't verify -> keep HIGH.
  if (!gitContext || !gitContext.isGitRepo) return 'high';

  // Walk the symlink chain. If ANY resolved candidate is tracked or has
  // history, keep HIGH. A symlinked .env pointing at a tracked file leaks
  // the same bytes as if .env itself were tracked.
  const resolved = gitContext.resolveCandidates(filePath);

  // Out-of-tree symlink target OR hardlink: we can't verify tracking
  // state of the other path holding the same bytes. Default HIGH.
  if (resolved.outOfTree || resolved.hardlinked) return 'high';

  for (const c of resolved.candidates) {
    if (gitContext.hasFileInIndex(c)) return 'high';
    if (gitContext.hasFileInHistory(c)) return 'high';
  }

  // Untracked AND not in history (any candidate). Local-only exposure.
  return 'medium';
}

/**
 * Build the rationale + recommendation strings for a downgraded .env
 * SEM-CRED-002 finding. Branches on whether the file is actually
 * gitignored vs just-untracked so the wording matches reality.
 */
function envDowngradeWording(
  filePath: string,
  gitContext?: GitContext,
): { rationale: string; recommendation: string } {
  const gitignored = gitContext?.isGitignored(filePath) ?? false;
  if (gitignored) {
    return {
      rationale: `${filePath} is gitignored and not present in version control history. The credential is local-only on disk. Treat as MEDIUM until confirmed; the secret may still have been shared via other channels (logs, screen-share, copy-paste, backups).`,
      recommendation: `Rotate this credential and migrate to opena2a protect (the Secretless vault keeps the value out of process memory and out of AI context, even on local disk).`,
    };
  }
  return {
    rationale: `${filePath} is not tracked in git and not in any add-history, but it is also NOT gitignored. The next \`git add .\` will commit this credential into version control. Treat as MEDIUM until \`.gitignore\` is updated; rotate the credential regardless.`,
    recommendation: `Add ${filePath} to .gitignore, rotate this credential, and migrate to opena2a protect (the Secretless vault keeps the value out of process memory and out of AI context).`,
  };
}

/**
 * For .env findings that stayed HIGH because the file is hardlinked or
 * points outside the repo (the bytes may be tracked under a path we can't
 * verify), return tailored wording so the user gets an actionable
 * verification step instead of the stock "Ensure .env is in .gitignore"
 * which may already be satisfied. Returns undefined when neither flag
 * applies; the caller should fall through to the standard wording.
 */
function envHighOverrideWording(
  filePath: string,
  gitContext?: GitContext,
): { rationale: string; recommendation: string } | undefined {
  if (!gitContext || !gitContext.isGitRepo) return undefined;
  const resolved = gitContext.resolveCandidates(filePath);
  if (resolved.hardlinked) {
    return {
      rationale: `${filePath} shares its inode with another path on disk (hardlinked). The other link may be tracked elsewhere in this repo, so the credential could be in version control under a different filename.`,
      recommendation: `Find the other hardlinked path with: find . -inum $(stat -f '%i' ${filePath} 2>/dev/null || stat -c '%i' ${filePath}). Verify whether any of those paths are tracked, rotate the credential, and migrate to opena2a protect.`,
    };
  }
  if (resolved.outOfTree) {
    return {
      rationale: `${filePath} is a symlink pointing outside this repo. The credential bytes live in a file this repo's git cannot inspect; treat as exposed until verified by checking the target's own repo (if any).`,
      recommendation: `Inspect the link target with: readlink ${filePath}. Verify whether the target is tracked in its own repository, rotate the credential, and migrate to opena2a protect.`,
    };
  }
  return undefined;
}

/**
 * The vocabulary a placeholder may OPEN with. Deliberately the same set
 * `isNonSecretValue` already uses — this gate exists to stop reporting
 * documentation, not to invent new reasons to stay quiet. An earlier draft
 * added `my`, `insert`, `enter`, `dummy` and `sample`; nothing justified them,
 * the suite stayed green without them, and `my` alone was enough to silence
 * `my-SuperSecretPassphrase` and `my_prod_db_password`.
 */
const PLACEHOLDER_WORDS = new Set(['your', 'todo', 'fixme', 'example', 'placeholder', 'change', 'replace']);

/** Longest a single word may be before it stops reading as prose. */
const MAX_PLACEHOLDER_WORD_CHARS = 12;
/** Longest the whole value may be before it stops reading as a placeholder. */
const MAX_PLACEHOLDER_CHARS = 40;

/**
 * All lowercase, or all uppercase. Placeholders are written in one case —
 * `your-password-here`, `YOUR_PASSWORD`. Mixed case is how secrets are written,
 * and it is the signal that survives when an attacker or a careless developer
 * borrows the vocabulary.
 */
function hasUniformCase(value: string): boolean {
  return value === value.toLowerCase() || value === value.toUpperCase();
}

/**
 * Is this URL password documentation rather than a leaked secret?
 *
 * Narrow on purpose, and local on purpose. The password slot of a connection
 * string carries no key to corroborate it — unlike every caller of
 * `isNonSecretValue`, where a SECRET_KEY_PATTERN key already asserted "secret"
 * and the value only has to veto. So the value must be shaped like a
 * placeholder, not merely open with the vocabulary:
 *
 *   1. An angle-bracket template whose body is wordy and single-cased:
 *      `<password>`, `<YOUR_PASSWORD>`. Brackets alone do not launder a
 *      secret — `<sk-proj-AAAABBBB>` is mixed case and stays reported.
 *   2. A vocabulary word, optionally continued by short same-case words joined
 *      with `-` or `_`, within an overall length bound.
 *
 * What that buys, each verified against the previous build:
 *
 *   your-password-here            placeholder   (suppressed)
 *   YOUR_PASSWORD                 placeholder   (suppressed)
 *   your-8Kd9fLm2QpXv7Zr4Nt6Bw1Hs secret, mixed case
 *   your-KdfLmQpXvZrNtBwHs        secret, mixed case — the digit-free form
 *   your_KJHGFDSAQWERTYUIOPZXC    secret, one 25-character "word"
 *   examplePassw0rd!              secret, mixed case and no separator
 *   change                        an imperative a user could have typed
 *
 * Anything not matched here is treated as a real credential. That direction is
 * deliberate: a false positive on a placeholder costs a user one suppression,
 * a false negative on a live database password costs them the database.
 */
function isPlaceholderUrlPassword(password: string): boolean {
  const trimmed = password.trim();
  if (!trimmed || trimmed.length > MAX_PLACEHOLDER_CHARS) return false;

  const angle = /^<([A-Za-z][A-Za-z0-9 _-]*)>$/.exec(trimmed);
  if (angle) return hasUniformCase(angle[1]);

  if (!hasUniformCase(trimmed)) return false;

  const words = trimmed.toLowerCase().split(/[-_]/);
  if (!PLACEHOLDER_WORDS.has(words[0])) return false;
  // `change` and `replace` only introduce a placeholder when they lead a phrase
  // (`change-me`, `replace-with-your-key`). Alone they are imperatives someone
  // could plausibly have typed as an actual password.
  if (words.length === 1 && (words[0] === 'change' || words[0] === 'replace')) return false;
  return words.slice(1).every((w) => w.length > 0 && w.length <= MAX_PLACEHOLDER_WORD_CHARS && /^[a-z]+$/.test(w));
}

/**
 * Detect URL-embedded passwords
 */
function detectUrlPasswords(file: AnalysisFile): SemanticFinding[] {
  const findings: SemanticFinding[] = [];
  const lines = file.content.split('\n');

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    URL_CREDENTIAL_PATTERN.lastIndex = 0;
    let match;

    while ((match = URL_CREDENTIAL_PATTERN.exec(line)) !== null) {
      const password = match[2];
      // Skip env var references in URLs
      if (password.startsWith('${') || password.startsWith('$')) continue;
      // Skip very short passwords that might be ports
      if (password.length < 3) continue;
      // A documented connection string is not a leaked one. This detector had
      // no value gate at all, so it was the last place the reported form-blank
      // complaint still reproduced: `postgres://admin:____________@host` and —
      // far more common — `mongodb://user:<password>@cluster0.mongodb.net/db`,
      // the verbatim MongoDB Atlas documentation string, both scored CRITICAL.
      //
      // Deliberately NOT `isNonSecretValue`. That function is written for a
      // key/value pair and assumes the key already asserted "secret", so the
      // value only has to veto. A URL password slot has no key, and routing it
      // through there imported rules that are wrong without one: it treats
      // `12345678`, `default`, `none` and `null` as non-secrets, and those are
      // precisely the leaked credentials this check exists to report. Measured
      // against the previous build, that silently dropped every numeric and
      // every keyword URL password.
      //
      // `isVisualFiller` covers the drawn blanks. Its floor is deliberately the
      // small one — a URL password of `hunter2` is real, and an 8-character
      // floor here would drop it.
      if (isPlaceholderUrlPassword(password)) continue;
      if (isVisualFiller(password, MIN_DRAWN_ONLY_CORE_CHARS)) continue;

      const urlPwMasked = password.length > 5 ? password.slice(0, 5) + '****' : '****';
      // Redact every occurrence of the raw password from the line before placing it
      // into structured evidence. Split-on-`:pw@` only catches the URL slot, but
      // the same secret can appear in comments, sibling assignments, or doc strings
      // on the same line. split/join catches all occurrences without partial-leak
      // and stays ES2020-safe (replaceAll is ES2021).
      const safeContent = line.split(password).join('[REDACTED]');
      findings.push({
        id: 'SEM-CRED-001',
        title: 'Password embedded in URL',
        description: `Database or service URL contains an inline password (${urlPwMasked}) in ${file.path}. Visible in plaintext in connection strings, logs, and process listings.`,
        rationale:
          'URL-embedded credentials are logged by proxies, shell history, and process listings. They bypass .env file protections and are easily leaked in stack traces.',
        category: 'credential',
        severity: severityForFile(file.path),
        file: file.path,
        line: i + 1,
        recommendation:
          'opena2a protect .  — migrates hardcoded secrets into the Secretless vault (local, keychain, 1Password, or HashiCorp Vault). Keys are injected at runtime; source files reference them by name only.',
        layer: 2,
        autoFixable: false,
        evidence: {
          kind: 'positive',
          lines: [
            {
              n: i + 1,
              content: safeContent.trim(),
              why: `URL contains inline password (${urlPwMasked}). Connection strings with embedded passwords are logged by proxies, shell history, and process listings, and bypass .env file protections.`,
            },
          ],
        },
        concept: 'secretless-vault',
      });
    }
  }

  return findings;
}

/**
 * Detect generic tokens via key-name heuristics.
 * Skips MCP config and Claude settings files — detectMcpEnvSecrets handles those
 * with richer context (server name, env block path) to avoid duplicate findings.
 */
function detectGenericTokens(file: AnalysisFile, gitContext?: GitContext): SemanticFinding[] {
  if (file.type === 'mcp_config' || file.type === 'claude_settings') {
    return [];
  }
  const findings: SemanticFinding[] = [];
  const lines = file.content.split('\n');

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    // JSON key:value patterns
    const jsonMatch = line.match(/"([^"]+)"\s*:\s*"([^"]+)"/);
    if (jsonMatch) {
      const [, key, value] = jsonMatch;
      if (SECRET_KEY_PATTERN.test(key) && !isNonSecretValue(value)) {
        // Ensure value looks like it could be a secret (min length, some entropy)
        if (looksLikeSecretValue(value)) {
          const { type, masked } = classifySecret(key, value);
          const sev = effectiveSeverityForEnvCredential(file.path, gitContext);
          const downgraded = sev === 'medium';
          const wording = downgraded
            ? envDowngradeWording(file.path, gitContext)
            : envHighOverrideWording(file.path, gitContext);
          findings.push({
            id: 'SEM-CRED-002',
            title: `${type} hardcoded in config`,
            description: `"${key}": ${masked}  -- ${type} hardcoded in ${file.path}. Visible to anyone with repo access or who can read the file.`,
            rationale: wording?.rationale ??
              'Config files with hardcoded secrets are commonly committed to version control. The key name and value prefix identify this as a real credential.',
            category: 'credential',
            severity: sev,
            file: file.path,
            line: i + 1,
            recommendation: wording?.recommendation ??
              'opena2a protect .  -- migrates hardcoded secrets into the Secretless vault (local, keychain, 1Password, or HashiCorp Vault). Keys are injected at runtime; source files reference them by name only.',
            layer: 2,
            autoFixable: false,
          });
        }
      }
    }

    // YAML key: value patterns
    const yamlMatch = line.match(/^(\s*)([a-zA-Z_][a-zA-Z0-9_-]*)\s*:\s*(.+)$/);
    if (yamlMatch && !jsonMatch) {
      const [, , key, rawValue] = yamlMatch;
      const value = rawValue.trim().replace(/^["']|["']$/g, '');
      if (SECRET_KEY_PATTERN.test(key) && !isNonSecretValue(value)) {
        if (looksLikeSecretValue(value)) {
          const { type, masked } = classifySecret(key, value);
          const sev = effectiveSeverityForEnvCredential(file.path, gitContext);
          const downgraded = sev === 'medium';
          const wording = downgraded
            ? envDowngradeWording(file.path, gitContext)
            : envHighOverrideWording(file.path, gitContext);
          findings.push({
            id: 'SEM-CRED-002',
            title: `${type} hardcoded in config`,
            description: `"${key}": ${masked}  -- ${type} hardcoded in ${file.path}. Visible to anyone with repo access or who can read the file.`,
            rationale: wording?.rationale ??
              'Config files with hardcoded secrets are commonly committed to version control. The key name and value prefix identify this as a real credential.',
            category: 'credential',
            severity: sev,
            file: file.path,
            line: i + 1,
            recommendation: wording?.recommendation ??
              'opena2a protect .  -- migrates hardcoded secrets into the Secretless vault (local, keychain, 1Password, or HashiCorp Vault). Keys are injected at runtime; source files reference them by name only.',
            layer: 2,
            autoFixable: false,
          });
        }
      }
    }

    // .env KEY=VALUE patterns
    const envMatch = line.match(/^([A-Z][A-Z0-9_]*)=(.+)$/);
    if (envMatch) {
      const [, key, rawValue] = envMatch;
      const value = rawValue.trim().replace(/^["']|["']$/g, '');
      if (SECRET_KEY_PATTERN.test(key) && !isNonSecretValue(value)) {
        if (looksLikeSecretValue(value)) {
          const sev = effectiveSeverityForEnvCredential(file.path, gitContext);
          const downgraded = sev === 'medium';
          const wording = downgraded
            ? envDowngradeWording(file.path, gitContext)
            : envHighOverrideWording(file.path, gitContext);
          findings.push({
            id: 'SEM-CRED-002',
            title: 'Hardcoded secret in config',
            description: `Environment variable "${key}" contains a hardcoded secret value in ${file.path}.`,
            rationale: wording?.rationale ??
              '.env files with hardcoded secrets should be gitignored. If this file is committed, the secret is exposed in version control history.',
            category: 'credential',
            severity: sev,
            file: file.path,
            line: i + 1,
            recommendation: wording?.recommendation ??
              `Ensure ${file.path} is in .gitignore and rotate this credential.`,
            layer: 2,
            autoFixable: false,
          });
        }
      }
    }
  }

  return findings;
}

/**
 * A SEM-CRED-003 pattern.
 *
 * `requiresEntropy: true` marks a pattern whose VALUE group is a bare
 * character-class run. Those admit a fill-in-the-blank form rule
 * (`Password: ________________________________`) as a credential, which is the
 * same defect class fixed in the AST-CRED entropy fallback, so the captured
 * value must clear `isVisualFiller` before a finding is raised. Patterns
 * carrying their own positive marker (a vendor prefix, `Bearer`) are accepted
 * on shape alone and set it `false`.
 *
 * The discriminated union makes `valueGroup` unreachable unless
 * `requiresEntropy` is `true`, so the two can never be written out of step.
 * TypeScript cannot prove that a RegExp literal actually HAS that group —
 * `broad-credential-patterns.test.ts` closes the remaining gap at CI time,
 * which is where this belongs; the previous runtime `throw` sat in a per-line
 * loop under a bare `catch`.
 */
type BroadCredentialPattern =
  | { readonly name: string; readonly pattern: RegExp; readonly requiresEntropy: false }
  | { readonly name: string; readonly pattern: RegExp; readonly requiresEntropy: true; readonly valueGroup: 1 };

/** Patterns that look like API keys/tokens (broader than core scanner's regex). */
export const BROAD_CREDENTIAL_PATTERNS: readonly BroadCredentialPattern[] = [
  { name: 'API key prefix', pattern: /(?:sk-|pk-|rk-|ak-)[a-zA-Z0-9_-]{16,}/g, requiresEntropy: false },
  { name: 'Bearer token', pattern: /Bearer\s+[a-zA-Z0-9._-]{20,}/g, requiresEntropy: false },
  { name: 'Generic long token', pattern: /(?:token|key|secret|password)\s*[=:]\s*['"]?([a-zA-Z0-9_-]{32,})['"]?/gi, requiresEntropy: true, valueGroup: 1 },
  { name: 'Base64 credential', pattern: /(?:password|secret|token|key)\s*[=:]\s*['"]?([A-Za-z0-9+/]{40,}={0,2})['"]?/gi, requiresEntropy: true, valueGroup: 1 },
];

/**
 * Detect credential-like strings in instruction files
 * (CLAUDE.md, .cursorrules, copilot-instructions.md)
 *
 * These files are loaded into the LLM context window,
 * so ANY credential here is critical severity.
 */
function detectCredentialsInInstructions(file: AnalysisFile): SemanticFinding[] {
  if (
    file.type !== 'agent_instructions' &&
    !file.path.toLowerCase().endsWith('claude.md') &&
    !file.path.toLowerCase().endsWith('.cursorrules')
  ) {
    return [];
  }

  const findings: SemanticFinding[] = [];
  const lines = file.content.split('\n');

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    for (const { name, pattern, requiresEntropy } of BROAD_CREDENTIAL_PATTERNS) {
      pattern.lastIndex = 0;
      // Walk EVERY match on the line, not just the first. A line can carry a
      // form blank and a real token together
      // (`password: ____…____  token: <real>`); taking only the first match
      // meant the rejected blank suppressed the credential beside it.
      let matched = false;
      let match: RegExpExecArray | null;
      while ((match = pattern.exec(line)) !== null) {
        if (!requiresEntropy) { matched = true; break; }
        // Every `requiresEntropy` pattern must capture its VALUE; scoring the
        // whole match would feed the `password:` descriptor into the filler
        // test and make the floor a no-op.
        //
        // A missing capture group FAILS CLOSED — the match is treated as a
        // credential. This used to `throw`, which was the wrong failure mode
        // twice over: `scanner.ts` wraps the whole structural pass in a bare
        // `catch` ("Structural analysis failure is non-fatal"), so the throw
        // deleted all four Layer 2 analyzers, produced no findings, and
        // IMPROVED the score. A silent detection loss that also looks like
        // success is the worst available outcome; extra findings are merely
        // noisy. `broad-credential-patterns.test.ts` asserts the table can
        // never reach this branch, so it is a backstop, not a code path.
        const value = match[1];
        if (value === undefined || !isVisualFiller(value)) { matched = true; break; }
        if (match.index === pattern.lastIndex) pattern.lastIndex++;
      }
      if (matched) {
        findings.push({
          id: 'SEM-CRED-003',
          title: 'Credential in agent instructions',
          description: `Detected ${name} pattern in ${file.path}. This file is loaded into the LLM context window.`,
          rationale:
            'Agent instruction files (CLAUDE.md, .cursorrules) are sent to the AI provider with every request. Any credential in these files is exposed to the AI provider and can be extracted via prompt injection attacks.',
          category: 'credential',
          severity: 'critical',
          file: file.path,
          line: i + 1,
          recommendation:
            'opena2a protect .  — scans for hardcoded secrets and encrypts them into a secure vault. Remove credentials from instruction files — they are sent to the AI provider on every request.',
          layer: 2,
          autoFixable: false,
        });
        break; // One finding per line
      }
    }
  }

  return findings;
}

/**
 * Detect secrets passed via MCP server env blocks
 */
function detectMcpEnvSecrets(file: AnalysisFile): SemanticFinding[] {
  if (file.type !== 'mcp_config' && file.type !== 'claude_settings') {
    return [];
  }

  const findings: SemanticFinding[] = [];

  let config: Record<string, unknown>;
  try {
    config = JSON.parse(file.content);
  } catch {
    return [];
  }

  const servers =
    (config as { mcpServers?: Record<string, { env?: Record<string, string> }> }).mcpServers || {};

  const lines = file.content.split('\n');

  for (const [serverName, serverConfig] of Object.entries(servers)) {
    if (!serverConfig.env) continue;

    for (const [key, value] of Object.entries(serverConfig.env)) {
      if (typeof value !== 'string') continue;
      // A DRAWN-BLANK gate, and deliberately nothing more. SEM-CRED-004 had a
      // key-name test and no value test, so the reported false positive
      // reproduced one file type over: an MCP onboarding template carrying
      // `"GITHUB_TOKEN": "________"` scored CRITICAL on a blank, exactly as the
      // `CLAUDE.md` checklist did.
      //
      // The floor is 2, NOT the shared `looksLikeSecretValue`. That helper
      // carries an 8-character length floor and an all-letters rejection, which
      // its other callers apply for their own reasons and this one never did —
      // routing through it silently stopped reporting `supersecretpassword`,
      // `correcthorsebatterystaple` and `hunt3r`, all real MCP env secrets that
      // `origin/main` reports, and raised the score by doing so. A suppression
      // added for blanks must suppress blanks and nothing else.
      if (
        SECRET_KEY_PATTERN.test(key) &&
        !isNonSecretValue(value) &&
        !isVisualFiller(value.trim().replace(/^["']|["']$/g, ''), MIN_DRAWN_ONLY_CORE_CHARS)
      ) {
        // Find the line number
        let lineNum: number | undefined;
        for (let i = 0; i < lines.length; i++) {
          if (lines[i].includes(`"${key}"`) && lines[i].includes(value.substring(0, 20))) {
            lineNum = i + 1;
            break;
          }
        }

        const { type: mcpSecType, masked: mcpMasked } = classifySecret(key, value);
        findings.push({
          id: 'SEM-CRED-004',
          title: `${mcpSecType} hardcoded in MCP server config`,
          description: `MCP server "${serverName}"  ${key}: ${mcpMasked}  — ${mcpSecType} hardcoded in env block of ${file.path}. MCP configs are commonly committed to version control.`,
          rationale:
            'MCP config files are typically committed to version control. Secrets in the env block are visible in plaintext and are extracted by any process that reads the config.',
          category: 'credential',
          severity: 'critical',
          file: file.path,
          line: lineNum,
          recommendation: 'opena2a protect .  — migrates hardcoded secrets into the Secretless vault (local, keychain, 1Password, or HashiCorp Vault). Keys are injected at runtime; source files reference them by name only.',
          layer: 2,
          autoFixable: false,
        });
      }
    }
  }

  return findings;
}

export class CredentialContextAnalyzer {
  analyze(files: AnalysisFile[], gitContext?: GitContext): SemanticFinding[] {
    const findings: SemanticFinding[] = [];

    for (const file of files) {
      findings.push(...detectUrlPasswords(file));
      findings.push(...detectGenericTokens(file, gitContext));
      findings.push(...detectCredentialsInInstructions(file));
      findings.push(...detectMcpEnvSecrets(file));
    }

    return findings;
  }
}
