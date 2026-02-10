import type { DLPPattern } from './types';

/** PII detection patterns */
export const PII_PATTERNS: DLPPattern[] = [
  {
    id: 'pii-ssn',
    name: 'Social Security Number',
    regex: /\b\d{3}-\d{2}-\d{4}\b/g,
    severity: 'critical',
    category: 'pii',
    maskStrategy: 'full',
  },
  {
    id: 'pii-email',
    name: 'Email Address',
    regex: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g,
    severity: 'medium',
    category: 'pii',
    maskStrategy: 'partial',
  },
  {
    id: 'pii-phone-us',
    name: 'US Phone Number',
    regex: /\b(?:\+1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/g,
    severity: 'medium',
    category: 'pii',
    maskStrategy: 'partial',
  },
  {
    id: 'pii-credit-card',
    name: 'Credit Card Number',
    regex: /\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6(?:011|5\d{2}))[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b/g,
    severity: 'critical',
    category: 'financial',
    maskStrategy: 'partial',
  },
  {
    id: 'pii-ipv4',
    name: 'IPv4 Address',
    regex: /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g,
    severity: 'low',
    category: 'infrastructure',
    maskStrategy: 'partial',
  },
  {
    id: 'pii-passport',
    name: 'US Passport Number',
    regex: /\b[A-Z]\d{8}\b/g,
    severity: 'high',
    category: 'pii',
    maskStrategy: 'full',
  },
  {
    id: 'pii-iban',
    name: 'IBAN',
    regex: /\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}(?:[A-Z0-9]?\d{0,16})\b/g,
    severity: 'high',
    category: 'financial',
    maskStrategy: 'partial',
  },
];
