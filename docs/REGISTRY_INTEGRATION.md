# OpenA2A Registry Integration

HackMyAgent can automatically report scan results to the OpenA2A Registry for centralized trust scoring and vulnerability tracking.

## Features

- **Automatic reporting:** Post scan results directly to the registry after scanning
- **Trust score updates:** Registry recalculates trust scores based on scan results
- **Transparency logging:** All scan results are logged to the immutable transparency log
- **Threat intelligence:** Critical findings trigger threat intelligence alerts

## Usage

### Secure Command (Hardening Scan)

```bash
npx hackmyagent secure <package-or-directory> \
  --registry-report \
  --version-id <uuid> \
  --registry-url https://registry.opena2a.org \
  --registry-key $REGISTRY_API_KEY
```

**Example:**
```bash
# Scan and report results to registry
npx hackmyagent secure @modelcontextprotocol/server-filesystem \
  --registry-report \
  --version-id d4e5f6a7-b8c9-0d1e-2f3a-4b5c6d7e8f9a \
  --registry-url https://registry.opena2a.org \
  --registry-key $REGISTRY_API_KEY
```

### Attack Command (Offensive Testing)

```bash
npx hackmyagent attack \
  --target http://localhost:3000 \
  --intensity high \
  --registry-report \
  --version-id <uuid> \
  --registry-url https://registry.opena2a.org \
  --registry-key $REGISTRY_API_KEY
```

**Example:**
```bash
# Run attack simulation and report to registry
npx hackmyagent attack \
  --target http://localhost:3000 \
  --local \
  --registry-report \
  --version-id d4e5f6a7-b8c9-0d1e-2f3a-4b5c6d7e8f9a \
  --registry-url https://registry.opena2a.org \
  --registry-key $REGISTRY_API_KEY
```

## Configuration

### Environment Variables

Instead of passing flags, you can set environment variables:

```bash
export REGISTRY_URL=https://registry.opena2a.org
export REGISTRY_API_KEY=your-api-key-here
```

Then use:
```bash
npx hackmyagent secure <package> --registry-report --version-id <uuid>
```

### Required Parameters

| Parameter | Flag | Environment | Required | Description |
|-----------|------|-------------|----------|-------------|
| Registry URL | `--registry-url` | `REGISTRY_URL` | Yes | Base URL of the registry API |
| API Key | `--registry-key` | `REGISTRY_API_KEY` | Yes | API key for authentication |
| Version ID | `--version-id` | - | Yes | UUID of the package version to report against |

## What Gets Reported

### Scan Report Format

```json
{
  "versionId": "d4e5f6a7-b8c9-0d1e-2f3a-4b5c6d7e8f9a",
  "scanId": "hma-1707123456789",
  "status": "failed",
  "completedAt": "2026-02-10T12:00:00Z",
  "vulnerabilities": [
    {
      "id": "FS-001",
      "severity": "high",
      "title": "Unrestricted file system access",
      "description": "Package has unrestricted read access to file system"
    }
  ],
  "criticalCount": 0,
  "highCount": 2,
  "mediumCount": 3,
  "lowCount": 1,
  "observedCapabilities": ["filesystem", "network"],
  "observedExternalApis": [],
  "capabilityMismatch": false,
  "behavioralFindings": [],
  "behavioralScore": 0,
  "rawReport": {
    "generator": "hackmyagent",
    "totalFindings": 42,
    "failedFindings": 6
  }
}
```

### Attack Report Format

```json
{
  "versionId": "d4e5f6a7-b8c9-0d1e-2f3a-4b5c6d7e8f9a",
  "scanId": "hma-attack-1707123456789",
  "status": "failed",
  "completedAt": "2026-02-10T12:00:00Z",
  "vulnerabilities": [
    {
      "id": "PROMPT-INJECTION-01",
      "severity": "critical",
      "title": "Prompt Injection: PROMPT-INJECTION-01",
      "description": "Attack succeeded - agent executed unauthorized action"
    }
  ],
  "criticalCount": 1,
  "highCount": 3,
  "mediumCount": 5,
  "lowCount": 2,
  "rawReport": {
    "generator": "hackmyagent-attack",
    "target": "http://localhost:3000",
    "riskRating": "high",
    "totalPayloads": 182,
    "successfulAttacks": 11
  }
}
```

## Registry Actions

When a scan result is reported, the registry automatically:

1. **Updates package version:**
   - Sets `scan_status` (passed, warnings, failed, error)
   - Updates vulnerability counts (critical, high, medium, low)
   - Stores scan report JSON in `scan_report` column
   - Sets `scanned_at` timestamp

2. **Logs to transparency log:**
   - Entry type: `scan_completed`
   - Includes scan ID, status, and counts
   - Immutable audit trail

3. **Recalculates trust score:**
   - Security scan factor (22% weight)
   - Behavioral verification factor (13% weight)
   - Updates overall trust level (0-4)

4. **Threat intelligence (if critical/high findings):**
   - Alerts threat intel service
   - May flag package for review
   - May block package if severe

## Error Handling

### Missing Parameters

```bash
$ npx hackmyagent secure . --registry-report
Error: --registry-url or REGISTRY_URL env is required for registry reporting
```

### Authentication Failure

```bash
$ npx hackmyagent secure . --registry-report --registry-url https://... --version-id ...
Registry report failed: Registry report failed (401): Unauthorized
```

### Version Not Found

```bash
$ npx hackmyagent secure . --registry-report --version-id invalid-uuid
Registry report failed: Registry report failed (404): Version not found
```

## Registry API Endpoints

### Internal Scan Result Endpoint

**POST** `/api/v1/registry/internal/scan-result`

**Headers:**
- `Content-Type: application/json`
- `Authorization: Bearer <api-key>`
- `User-Agent: HackMyAgent-CLI`

**Request Body:** See "Scan Report Format" above

**Response (Success):**
```json
{
  "message": "Scan result processed",
  "versionId": "d4e5f6a7-b8c9-0d1e-2f3a-4b5c6d7e8f9a"
}
```

**Response (Error):**
```json
{
  "error": "Version not found"
}
```

### Additional Endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/v1/registry/internal/trigger-scan/:versionId` | POST | Manually trigger a scan |
| `/api/v1/registry/internal/simulate-scan/:versionId?severity=high` | POST | Simulate scan for testing |
| `/api/v1/registry/internal/drift/:versionId` | GET | Check for capability drift |
| `/api/v1/registry/internal/recalculate-trust/:versionId` | POST | Manually recalculate trust |

## End-to-End Testing

### 1. Test with Simulated Scan (No HackMyAgent Required)

```bash
# Simulate a scan with high severity findings
curl -X POST https://registry.opena2a.org/api/v1/registry/internal/simulate-scan/{versionId}?severity=high \
  -H "Authorization: Bearer $REGISTRY_API_KEY"
```

### 2. Test with Real Scan + Registry Report

```bash
# Get a package version ID from the registry
VERSION_ID=$(curl https://registry.opena2a.org/api/v1/registry/packages | jq -r '.[0].versions[0].id')

# Run HackMyAgent with registry reporting
npx hackmyagent secure @modelcontextprotocol/server-filesystem \
  --registry-report \
  --version-id $VERSION_ID \
  --registry-url https://registry.opena2a.org \
  --registry-key $REGISTRY_API_KEY

# Verify scan results were recorded
curl https://registry.opena2a.org/api/v1/registry/versions/$VERSION_ID | jq '.scan_status, .vulnerability_count'
```

### 3. Test Attack Mode + Registry Report

```bash
# Run attack simulation locally and report to registry
npx hackmyagent attack \
  --local \
  --intensity medium \
  --registry-report \
  --version-id $VERSION_ID \
  --registry-url https://registry.opena2a.org \
  --registry-key $REGISTRY_API_KEY
```

## CI/CD Integration

### GitHub Actions

```yaml
- name: Scan and report to registry
  run: |
    npx hackmyagent secure . \
      --registry-report \
      --version-id ${{ secrets.REGISTRY_VERSION_ID }} \
      --registry-url ${{ secrets.REGISTRY_URL }} \
      --registry-key ${{ secrets.REGISTRY_API_KEY }}
```

### Docker Scanner Worker

```dockerfile
FROM node:20-alpine
RUN npm install -g hackmyagent@latest

ENTRYPOINT ["npx", "hackmyagent", "secure"]
CMD ["--registry-report"]
```

## Security Considerations

- **API Key Storage:** Store `REGISTRY_API_KEY` as a secret (GitHub Secrets, env vars, Vault)
- **Key Rotation:** Registry API keys should be rotated periodically
- **Endpoint Security:** `/internal/*` endpoints should be restricted (API key auth, IP whitelist)
- **Rate Limiting:** Registry may rate-limit scan result submissions

## Trust Score Impact

Scan results affect trust score through two factors:

### 1. Security Scan Factor (22% of total score)

| Result | Score Impact |
|--------|--------------|
| OASB scan passed (0 critical/high) | +22 points |
| No critical findings | +15 points |
| No high findings | +7 points |
| Critical or high findings | 0 points |

### 2. Behavioral Verification Factor (13% of total score)

| Condition | Score Impact |
|-----------|--------------|
| Capabilities match behavior | +13 points |
| No suspicious activity | +10 points |
| Sandbox tested | +3 points |
| Capability mismatch | 0 points |

## Troubleshooting

### Issue: "Registry report failed (401)"
**Solution:** Check that `REGISTRY_API_KEY` is valid and not expired

### Issue: "Registry report failed (404): Version not found"
**Solution:** Verify the `--version-id` UUID exists in the registry

### Issue: "HackMyAgent service not configured"
**Solution:** Registry backend needs `HackMyAgentService` initialized

### Issue: Scan works but no trust score change
**Solution:** Wait for background trust recalculation job, or manually trigger:
```bash
curl -X POST https://registry.opena2a.org/api/v1/registry/internal/recalculate-trust/$VERSION_ID \
  -H "Authorization: Bearer $REGISTRY_API_KEY"
```

## Further Reading

- [HackMyAgent Documentation](https://github.com/ecolibria/hackmyagent)
- [OpenA2A Registry API Docs](https://registry.opena2a.org/docs)
- [Trust Scoring Algorithm](https://github.com/opena2a-org/opena2a-registry/blob/main/QUALITY_ASSURANCE_REPORT.md)
- [OASB Attack Scenarios](https://oasb.ai/)
