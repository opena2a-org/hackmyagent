import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import type { AuditEvent, AuditEventInput, AuditReadOptions } from './types';

const AUDIT_FILE = 'audit.jsonl';

/** Append an audit event to the JSON-lines log */
export function logEvent(dataDir: string, event: AuditEventInput): AuditEvent {
  const fullEvent: AuditEvent = {
    timestamp: new Date().toISOString(),
    ...event,
  };

  // Enforce per-field size limits to prevent DoS via oversized fields
  const MAX_FIELD_SIZE = 4096;
  if (fullEvent.plugin.length > MAX_FIELD_SIZE) fullEvent.plugin = fullEvent.plugin.slice(0, MAX_FIELD_SIZE);
  if (fullEvent.action.length > MAX_FIELD_SIZE) fullEvent.action = fullEvent.action.slice(0, MAX_FIELD_SIZE);
  if (fullEvent.target.length > MAX_FIELD_SIZE) fullEvent.target = fullEvent.target.slice(0, MAX_FIELD_SIZE);

  // Enforce per-event size limit (1MB) to prevent DoS via oversized metadata
  const MAX_EVENT_SIZE = 1024 * 1024;
  let serialized = JSON.stringify(fullEvent);
  if (serialized.length > MAX_EVENT_SIZE) {
    fullEvent.metadata = { _truncated: true, _reason: 'Event exceeded 1MB size limit' };
    serialized = JSON.stringify(fullEvent);
  }

  fs.mkdirSync(dataDir, { recursive: true });
  const filePath = path.join(dataDir, AUDIT_FILE);

  // Rotate if audit log exceeds 50MB, keep last 5 rotated logs
  const MAX_AUDIT_SIZE = 50 * 1024 * 1024;
  const MAX_ROTATED_LOGS = 5;
  try {
    const stat = fs.statSync(filePath);
    if (stat.size > MAX_AUDIT_SIZE) {
      const suffix = `${Date.now()}.${process.pid}.${crypto.randomBytes(4).toString('hex')}`;
      const rotatedPath = `${filePath}.${suffix}`;
      try {
        fs.renameSync(filePath, rotatedPath);
      } catch {
        // Another process may have already rotated — safe to continue
      }

      // Clean up old rotated logs beyond the retention limit
      try {
        const dir = path.dirname(filePath);
        const base = path.basename(filePath);
        const rotated = fs.readdirSync(dir)
          .filter((f: string) => f.startsWith(base + '.') && f !== base)
          .sort()
          .reverse();
        for (const old of rotated.slice(MAX_ROTATED_LOGS)) {
          try {
            fs.unlinkSync(path.join(dir, old));
          } catch {
            // Individual file deletion is best-effort
          }
        }
      } catch {
        // Cleanup is best-effort
      }
    }
  } catch {
    // File doesn't exist yet — will be created by appendFileSync
  }

  fs.appendFileSync(filePath, serialized + '\n', 'utf-8');

  return fullEvent;
}

/** Read audit events from the JSON-lines log */
export function readAuditLog(
  dataDir: string,
  options?: AuditReadOptions
): AuditEvent[] {
  const filePath = path.join(dataDir, AUDIT_FILE);
  if (!fs.existsSync(filePath)) {
    return [];
  }

  const raw = fs.readFileSync(filePath, 'utf-8');
  const lines = raw.trim().split('\n').filter(Boolean);

  let events: AuditEvent[] = lines.map((line) => JSON.parse(line) as AuditEvent);

  if (options?.since) {
    const sinceDate = new Date(options.since).getTime();
    events = events.filter((e) => new Date(e.timestamp).getTime() > sinceDate);
  }

  if (options?.limit && options.limit > 0) {
    // Return the most recent N events
    events = events.slice(-options.limit);
  }

  return events;
}

/** Check if the audit log exists and has entries */
export function hasAuditLog(dataDir: string): boolean {
  const filePath = path.join(dataDir, AUDIT_FILE);
  if (!fs.existsSync(filePath)) return false;
  const stat = fs.statSync(filePath);
  return stat.size > 0;
}
