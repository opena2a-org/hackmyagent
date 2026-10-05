# OpenA2A Registry Integration

HackMyAgent can report scan results to the OpenA2A Registry, where they feed trust scoring and vulnerability tracking for a registered package version.

## Features

- **Reporting on request:** `--version-id` (or `--registry-report`) posts the results of the scan that just ran
- **Trust score updates:** Registry recalculates trust scores based on scan results
- **Transparency logging:** All scan results are logged to the immutable transparency log
- **Threat intelligence:** Critical or high findings trigger threat intelligence alerts

## Usage

There are two reporting paths:

- **Authenticated (`--version-id <uuid>`):** reports against one registered package version. Needs a Registry API key.
- **Community (`--registry-report` without `--version-id`):** submits the scan for the package the scanned directory declares (its `package.json` name, else the directory name), with a short-lived scan token the CLI requests itself. No API key.

The Registry API host is `https://api.oa2a.org`, the CLI default.

### Secure Command (Hardening Scan)

`secure` scans a directory. To check a published package by name, use `check <package>`; to report a scan of a published package, scan its source directory (see [End-to-End Testing](#2-test-with-real-scan--registry-report)).

```bash
npx hackmyagent secure <directory> \
  --version-id <uuid> \
  --registry-key $REGISTRY_API_KEY
```

**Example:**
```bash
# Scan a package's source directory and report the results to the Registry
npx hackmyagent secure ./server-filesystem \
  --version-id d4e5f6a7-b8c9-0d1e-2f3a-4b5c6d7e8f9a \
  --registry-key $REGISTRY_API_KEY
```

On success it prints `Registry: scan results reported for version <uuid>`.

### Attack Command (Offensive Testing)

The target is a positional argument. `--intensity` takes `passive`, `active` (default) or `aggressive`.

```bash
npx hackmyagent attack <target-url> \
  --intensity aggressive \
  --version-id <uuid> \
  --registry-key $REGISTRY_API_KEY
```

**Example:**
```bash
# Attack a running agent and report the results to the Registry
npx hackmyagent attack http://localhost:3000 \
  --version-id d4e5f6a7-b8c9-0d1e-2f3a-4b5c6d7e8f9a \
  --registry-key $REGISTRY_API_KEY
```

On success it prints `Registry: attack results reported for version <uuid>`.

Only a run that measured the target is reported. `attack --local` contacts no agent, and neither does an unreachable target, so either prints `Registry: not reported — this run measured nothing about the target.` and sends nothing.

## Configuration

### Environment Variables

Instead of passing flags, you can set environment variables:

```bash
export REGISTRY_API_KEY=your-api-key-here
export REGISTRY_URL=https://api.oa2a.org   # optional: this is the default
```

Then use:
```bash
npx hackmyagent secure <directory> --version-id <uuid>
```

### Parameters

| Parameter | Flag | Environment | Required | Description |
|-----------|------|-------------|----------|-------------|
| Version ID | `--version-id` | - | For authenticated reporting | UUID of the package version to report against |
| API Key | `--registry-key` | `REGISTRY_API_KEY` | With `--version-id` | Registry token with the `internal:scans:write` scope, sent as `Authorization: Bearer <key>` |
| ATC token | - | `ATC_TOKEN` | No | When set, sent as `Authorization: ATC <token>` in place of the API key |
| Registry URL | `--registry-url` | `REGISTRY_URL` | No | Registry API base URL; default `https://api.oa2a.org` |

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
      "id": "ATK-PI-001",
      "severity": "critical",
      "title": "prompt-injection: ATK-PI-001",
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
    "totalPayloads": 164,
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
   - Security scan factor (30% weight)
   - Behavioral verification factor (5% weight)
   - Updates overall trust level (0-4)

4. **Threat intelligence (if critical/high findings or a capability mismatch):**
   - Alerts threat intel service
   - May flag package for review
   - May block package if severe

## Error Handling

### Missing API Key

```bash
$ npx hackmyagent secure . --version-id <uuid>
Error: --registry-key or REGISTRY_API_KEY env is required when using --version-id
```

The command exits 1.

### Rejected or Failed Report

A report the Registry rejects (401, 403, 404) or that cannot reach it does not change the scan's output or exit code, and no error is printed. The confirmation line (`Registry: scan results reported for version <uuid>`) is printed only when the Registry accepted the report; if it is missing, the report was not recorded. See [Troubleshooting](#troubleshooting).

### Scan That Reached No Verdict

When the scan reaches no verdict (inputs it discovered but could not read, or a `--deep` layer that did not finish), nothing is sent, and stderr says so: `Registry: nothing sent — <reason>. Withheld: --version-id. <remedy>`

## Registry API Endpoints

### Internal Scan Result Endpoint

**POST** `/internal/scan-result` (on the API host, for example `https://api.oa2a.org/internal/scan-result`)

**Headers:**
- `Content-Type: application/json`
- `Authorization: Bearer <api-key>` (scope `internal:scans:write`)
- `User-Agent: HackMyAgent-CLI`

**Request Body:** See "Scan Report Format" above

**Response (Success):**
```json
{
  "message": "Scan result processed",
  "versionId": "d4e5f6a7-b8c9-0d1e-2f3a-4b5c6d7e8f9a",
  "scanRequestId": null
}
```

**Response (Error):**
```json
{
  "error": "Version ID is required"
}
```

### Additional Endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/internal/trigger-scan/:versionId` | POST | Manually trigger a scan |
| `/internal/simulate-scan/:versionId?severity=high` | POST | Simulate scan for testing |
| `/internal/drift/:versionId` | GET | Check for capability drift (scope `internal:scans:read`) |
| `/internal/recalculate-trust/:versionId` | POST | Manually recalculate trust |
| `/api/v1/registry/packages/:id/versions` | GET | Read a package's versions, including `scanStatus` and `vulnerabilityCount` (public) |

## End-to-End Testing

### 1. Test with Simulated Scan (No HackMyAgent Required)

```bash
# Simulate a scan with high severity findings
curl -X POST "https://api.oa2a.org/internal/simulate-scan/$VERSION_ID?severity=high" \
  -H "Authorization: Bearer $REGISTRY_API_KEY"
```

### 2. Test with Real Scan + Registry Report

```bash
# Pick a registered package: prints its id, name, latest version and that version's id
curl -s 'https://api.oa2a.org/api/v1/registry/packages?type=mcp_server&limit=1' \
  | jq -r '.packages[0] | .id, .name, .latestVersion, .latestVersionId'
PACKAGE_ID=<id>
VERSION_ID=<latestVersionId>

# Fetch that version's source into a directory
npm pack <name>@<latestVersion>
mkdir pkg && tar -xzf ./*.tgz -C pkg --strip-components=1

# Scan it and report to the Registry
npx hackmyagent secure pkg \
  --version-id $VERSION_ID \
  --registry-key $REGISTRY_API_KEY

# Verify scan results were recorded
curl -s "https://api.oa2a.org/api/v1/registry/packages/$PACKAGE_ID/versions" \
  | jq --arg v "$VERSION_ID" '.versions[] | select(.id == $v) | {scanStatus, vulnerabilityCount}'
```

### 3. Test Attack Mode + Registry Report

```bash
# Attack a running agent and report the results to the Registry.
# --local runs are never reported: they contact no agent.
npx hackmyagent attack http://localhost:3000 \
  --intensity active \
  --version-id $VERSION_ID \
  --registry-key $REGISTRY_API_KEY
```

## CI/CD Integration

### GitHub Actions

```yaml
- name: Scan and report to registry
  run: |
    npx hackmyagent secure . \
      --version-id ${{ secrets.REGISTRY_VERSION_ID }} \
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

A reported scan feeds the Registry's security scan factor. The Registry scores each trust factor from 0 to 1 and weights it:

| Factor | Weight |
|--------|--------|
| Security scan (HackMyAgent scan results) | 30% |
| Platform validation | 30% |
| Publisher verification | 15% |
| Dependency health | 15% |
| Behavioral verification (runtime observation) | 5% |
| SLSA provenance | 3% |
| Signature integrity | 2% |

## Troubleshooting

### Issue: no `Registry: scan results reported` line after a `--version-id` scan
**Solution:** The Registry did not accept the report. Check that:
- `REGISTRY_API_KEY` is valid, not expired, and carries the `internal:scans:write` scope
- the `--version-id` UUID exists in the registry
- `REGISTRY_URL` (or `--registry-url`), if set, points at the API host `https://api.oa2a.org`

### Issue: Scan works but no trust score change
**Solution:** Wait for background trust recalculation job, or manually trigger:
```bash
curl -X POST https://api.oa2a.org/internal/recalculate-trust/$VERSION_ID \
  -H "Authorization: Bearer $REGISTRY_API_KEY"
```

## Further Reading

- [HackMyAgent Documentation](https://github.com/opena2a-org/hackmyagent)
- [OASB Attack Scenarios](https://oasb.ai/)
