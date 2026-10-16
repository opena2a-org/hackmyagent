// Drafts the first reply to a support ticket, with SOUL.md as the system prompt.
const fs = require('node:fs');
const path = require('node:path');
const Anthropic = require('@anthropic-ai/sdk');

const soul = fs.readFileSync(path.join(__dirname, '..', 'SOUL.md'), 'utf8');
const anthropic = new Anthropic();

async function firstReply(ticket) {
  const answer = await anthropic.messages.create({
    model: process.env.TRIAGE_MODEL,
    max_tokens: 800,
    system: soul,
    messages: [{ role: 'user', content: `${ticket.subject}\n\n${ticket.body}` }],
  });
  return answer.content[0].text;
}

module.exports = { firstReply };
