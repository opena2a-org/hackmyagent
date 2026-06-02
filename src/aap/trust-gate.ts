/**
 * AAP gate for `hackmyagent trust`. Calls the local Secretless broker before any
 * Registry lookup. Mirrors the exit-code model + hardening of opena2a-cli's
 * `protect --grant` gate (opena2a-org/opena2a#179). Returns 0 to proceed,
 * non-zero to abort.
 */
import * as fs from 'node:fs';

import {
  BrokerClient,
  BrokerGrantError,
  BrokerUnexpectedStatusError,
  DEFAULT_SOCKET_PATH,
  GrantDeniedError,
} from './client';

const MAX_ATX_FILE_BYTES = 256 * 1024;

function sanitizeForTty(s: string): string {
  return s.replace(/[\x00-\x08\x0b-\x1f\x7f]/g, '?');
}

function isStructurallyValidAtx(value: unknown): value is Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const v = value as Record<string, unknown>;
  return typeof v.atcVersion === 'string' && typeof v.agentId === 'string';
}

export interface TrustAapGateOptions {
  grant: string;
  atxPath?: string;
  brokerSocket?: string;
  brokerTokenPath?: string;
  grantAgentId?: string;
  packageName?: string;
  json?: boolean;
}

export async function trustAapGate(options: TrustAapGateOptions): Promise<number> {
  const grant = sanitizeForTty(options.grant);
  const isJson = options.json === true;

  if (!options.atxPath) {
    process.stderr.write('--grant requires --atx <path-to-atx.json>\n');
    process.stderr.write('  Issue an ATX from your AIM identity and pass its JSON file path.\n');
    return 2;
  }

  try {
    const stat = fs.statSync(options.atxPath);
    if (stat.size > MAX_ATX_FILE_BYTES) {
      process.stderr.write(`ATX file at ${options.atxPath} is ${stat.size} bytes; expected <= ${MAX_ATX_FILE_BYTES}\n`);
      return 2;
    }
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    if (code === 'ENOENT') {
      process.stderr.write(`ATX file not found: ${options.atxPath}\n`);
      process.stderr.write('  Pass --atx <path> pointing to a JSON ATX issued by your AIM identity.\n');
    } else if (code === 'EACCES') {
      process.stderr.write(`Permission denied reading ATX file: ${options.atxPath}\n`);
    } else {
      process.stderr.write(`Could not read ATX file at ${options.atxPath}\n`);
    }
    return 2;
  }

  let atx: unknown;
  try {
    const raw = fs.readFileSync(options.atxPath, 'utf-8');
    atx = JSON.parse(raw);
  } catch (err) {
    process.stderr.write(`Could not parse ATX file at ${options.atxPath}: ${(err as Error).message}\n`);
    return 2;
  }
  if (!isStructurallyValidAtx(atx)) {
    process.stderr.write(`ATX file at ${options.atxPath} is not a valid ATX object (missing atcVersion or agentId)\n`);
    return 2;
  }

  const socketPath = options.brokerSocket ?? DEFAULT_SOCKET_PATH;
  if (!options.brokerSocket) {
    try {
      const stat = fs.statSync(socketPath);
      const myUid = typeof process.getuid === 'function' ? process.getuid() : -1;
      if (myUid !== -1 && stat.uid !== myUid) {
        process.stderr.write(`Refusing to connect to broker socket ${socketPath}: owned by uid ${stat.uid}, expected ${myUid}\n`);
        process.stderr.write('  This protects against impostor brokers on multi-user systems.\n');
        return 4;
      }
    } catch {
      // Socket missing surfaces later as a connection failure with a clearer message.
    }
  }

  const client = new BrokerClient({
    socketPath: options.brokerSocket,
    tokenPath: options.brokerTokenPath,
  });

  try {
    // Sanitized `grant` is used ONLY for stderr writes (sanitizeForTty strips
    // ANSI / C0 escapes so a malicious --grant cannot inject terminal control
    // sequences). The broker receives `options.grant` unmodified because the
    // signed audit-log entry must preserve byte-identical input for AAP §6.6
    // attribution. If the broker ever begins echoing the audit log to a TTY,
    // it -- not this consumer -- owns the sanitization decision.
    await client.grant({
      agentId: options.grantAgentId ?? 'hackmyagent_trust_cli',
      atx,
      grant: options.grant,
      operation: {
        method: 'GET',
        path: '/trust/check',
        query: options.packageName ? { package: options.packageName } : {},
      },
    });
    return 0;
  } catch (err) {
    if (err instanceof GrantDeniedError) {
      if (isJson) {
        process.stdout.write(JSON.stringify({
          status: 'aap-denied',
          grant: options.grant,
          packageName: options.packageName,
          remediation: `Verify your broker policy binds ${options.grant} to your agent's trust class.`,
        }) + '\n');
      } else {
        process.stderr.write(`AAP broker denied ${grant}\n`);
        process.stderr.write('\n');
        process.stderr.write('The Secretless broker is the policy decision point for this operation.\n');
        process.stderr.write("The broker returned an opaque denial; reasons live only in the broker's signed audit log (AAP §6.6).\n");
        process.stderr.write('\n');
        process.stderr.write(`Next step: review the broker's grant policy for ${grant}.\n`);
        process.stderr.write('  Default policy dir:  ~/.secretless-ai/policies/\n');
        process.stderr.write('  Audit log:           ~/.secretless-ai/broker.audit.log\n');
      }
      return 3;
    }
    if (err instanceof BrokerUnexpectedStatusError) {
      process.stderr.write(`AAP broker returned status ${err.status}; refusing to proceed.\n`);
      process.stderr.write('  Reasons live only in the broker audit log (~/.secretless-ai/broker.audit.log).\n');
      return 6;
    }
    if (err instanceof BrokerGrantError) {
      process.stderr.write(`AAP broker unreachable: ${sanitizeForTty(err.message)}\n`);
      process.stderr.write('  Start the broker:  secretless broker start\n');
      return 4;
    }
    process.stderr.write(`AAP gate failed unexpectedly: ${sanitizeForTty((err as Error).message)}\n`);
    return 5;
  }
}
