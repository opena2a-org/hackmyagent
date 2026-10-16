// Drafts release notes from the pull requests merged since the last tag.
const { Octokit } = require('@octokit/rest');
const Anthropic = require('@anthropic-ai/sdk');

// Both credentials come from the environment, filled from the vault at start-up.
const github = new Octokit({ auth: process.env.GITHUB_TOKEN });
const anthropic = new Anthropic();

async function draftNotes(owner, repo, since) {
  const { data } = await github.pulls.list({ owner, repo, state: 'closed', per_page: 100 });
  const merged = data
    .filter((pr) => pr.merged_at && pr.merged_at > since)
    .map((pr) => `- ${pr.title} (#${pr.number})`);
  const answer = await anthropic.messages.create({
    model: process.env.NOTES_MODEL,
    max_tokens: 2000,
    messages: [{ role: 'user', content: `Group these changes into release notes:\n${merged.join('\n')}` }],
  });
  return answer.content[0].text;
}

module.exports = { draftNotes };
