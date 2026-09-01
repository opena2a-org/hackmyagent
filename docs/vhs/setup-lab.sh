#!/bin/bash
# Set up a demo project for HackMyAgent VHS recordings.
# Creates /tmp/hma-demo with an AI agent project that has security issues.

set -e

LAB_DIR="/tmp/hma-demo"
rm -rf "$LAB_DIR"
mkdir -p "$LAB_DIR" && cd "$LAB_DIR"
git init -q

cat > package.json << 'EOF'
{
  "name": "demo-agent",
  "version": "1.0.0",
  "main": "index.js"
}
EOF

mkdir -p .claude
cat > .claude/settings.json << 'EOF'
{
  "permissions": {
    "allow": ["Read", "Write", "Bash(*)", "mcp__filesystem(*)"],
    "deny": []
  }
}
EOF

cat > CLAUDE.md << 'EOF'
# Demo Agent
You are an AI assistant. You have full access to the filesystem.
EOF

cat > mcp.json << 'EOF'
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "/"]
    }
  }
}
EOF

cat > .env << 'EOF'
OPENAI_API_KEY=sk-proj-fake1234567890abcdefghijklmnop
DATABASE_URL=postgres://admin:password123@localhost:5432/mydb
EOF

cat > index.js << 'EOF'
const API_KEY = "sk-ant-api03-fake123456789";
module.exports = { API_KEY };
EOF

git add -A && git commit -m "Initial commit" -q
echo "Lab ready: $LAB_DIR"
