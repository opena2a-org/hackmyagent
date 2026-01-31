# Contributing to HackMyAgent

We welcome contributions to HackMyAgent. Here's how to get started.

## Development Setup

```bash
# Clone the repo
git clone https://github.com/opena2a-org/hackmyagent.git
cd hackmyagent

# Install dependencies
npm install

# Build
npm run build

# Run tests
npm test
```

## Project Structure

```
packages/
  core/     # Core scanning and verification logic
  cli/      # Command-line interface
```

## Making Changes

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Make your changes
4. Run tests (`npm test`)
5. Commit with a clear message
6. Push and open a pull request

## Code Style

- TypeScript with strict mode
- Tests for all new functionality
- Clear, descriptive variable names

## Adding Security Checks

New security checks go in `packages/core/src/hardening/scanner.ts`. Each check needs:

- Unique check ID (e.g., `SEC-004`)
- Name and description
- Severity level (critical, high, medium, low)
- Category
- Detection logic
- Optional auto-fix logic

Add corresponding tests in `scanner.test.ts`.

## Reporting Security Issues

For security vulnerabilities, please email info@opena2a.org instead of opening a public issue.

## License

By contributing, you agree that your contributions will be licensed under the Apache-2.0 License.
