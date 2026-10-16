// Turns an on-call request into runbook commands and runs them on this host.
const fs = require('node:fs');
const path = require('node:path');
const { execSync } = require('node:child_process');
const Anthropic = require('@anthropic-ai/sdk');

const RUNBOOK_DIR = path.join(__dirname, '..', 'runbooks');
const client = new Anthropic();

async function run(request) {
  const runbooks = fs.readdirSync(RUNBOOK_DIR)
    .map((name) => `## ${name}\n${fs.readFileSync(path.join(RUNBOOK_DIR, name), 'utf8')}`)
    .join('\n\n');
  const answer = await client.messages.create({
    model: process.env.RUNBOOK_MODEL,
    max_tokens: 1500,
    system: `Reply with the shell commands, one per line, that carry out the request.\n\n${runbooks}`,
    messages: [{ role: 'user', content: request }],
  });
  for (const command of answer.content[0].text.split('\n').filter(Boolean)) {
    process.stdout.write(execSync(command, { encoding: 'utf8' }));
  }
}

run(process.argv.slice(2).join(' '));
