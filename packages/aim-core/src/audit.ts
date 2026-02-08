import * as fs from 'fs';
import * as path from 'path';
import type { AuditEvent, AuditEventInput, AuditReadOptions } from './types';

const AUDIT_FILE = 'audit.jsonl';

/** Append an audit event to the JSON-lines log */
export function logEvent(dataDir: string, event: AuditEventInput): AuditEvent {
  const fullEvent: AuditEvent = {
    timestamp: new Date().toISOString(),
    ...event,
  };

  fs.mkdirSync(dataDir, { recursive: true });
  const filePath = path.join(dataDir, AUDIT_FILE);

  // Rotate if audit log exceeds 50MB
  const MAX_AUDIT_SIZE = 50 * 1024 * 1024;
  try {
    const stat = fs.statSync(filePath);
    if (stat.size > MAX_AUDIT_SIZE) {
      const rotatedPath = filePath + '.' + Date.now();
      fs.renameSync(filePath, rotatedPath);
    }
  } catch {
    // File doesn't exist yet — will be created by appendFileSync
  }

  fs.appendFileSync(filePath, JSON.stringify(fullEvent) + '\n', 'utf-8');

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
