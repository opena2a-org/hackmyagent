# DNS Verification for Publishers

Publishers can verify their identity by adding a DNS TXT record to their domain. This proves ownership and increases trust scores for their skills.

## How It Works

When you run `hackmyagent check @publisher/skill`, the tool:

1. Looks up DNS TXT records for `publisher.dev`, `publisher.com`, `publisher.io`, etc.
2. Searches for a record containing `hackmyagent-verify=publisher`
3. If found, marks the publisher as verified

## Setting Up Verification

### Step 1: Choose Your Domain

Use a domain you control that matches your publisher name. For example:
- Publisher: `@opena2a/...` → Domain: `opena2a.dev`
- Publisher: `@mycompany/...` → Domain: `mycompany.com`

### Step 2: Add a TXT Record

Add a TXT record to your domain's DNS settings:

**Option A: Root domain**
```
Type: TXT
Host: @ (or leave blank)
Value: hackmyagent-verify=your-publisher-name
```

**Option B: Subdomain (recommended)**
```
Type: TXT
Host: _hackmyagent
Value: publisher=your-publisher-name
```

### Step 3: Verify

Wait for DNS propagation (usually 5-60 minutes), then test:

```bash
# Check your skill
npx hackmyagent check @your-publisher/any-skill

# Verify DNS directly
dig TXT your-domain.com
dig TXT _hackmyagent.your-domain.com
```

## Accepted TXT Record Formats

Any of these formats work (case-insensitive):

```
hackmyagent-verify=publisher-name
hackmyagent-publisher=publisher-name
opena2a-verify=publisher-name
publisher=publisher-name  # Only for _hackmyagent subdomain
```

## Example

For a publisher named `acme`:

```
# DNS Zone File
acme.dev.       IN TXT "hackmyagent-verify=acme"

# Or using subdomain
_hackmyagent.acme.dev.  IN TXT "publisher=acme"
```

## Troubleshooting

### "Not verified" even after adding TXT record

1. Wait for DNS propagation (up to 24 hours for some providers)
2. Verify the record exists: `dig TXT your-domain.com`
3. Check spelling matches exactly (case-insensitive)
4. Try the `--verbose` flag for detailed output

### Multiple TXT records

It's fine to have multiple TXT records (SPF, DKIM, etc.). The verifier only looks for hackmyagent-specific records.

### Custom domain mapping

If your publisher name doesn't match your domain, contact us to add a custom mapping to the registry.
