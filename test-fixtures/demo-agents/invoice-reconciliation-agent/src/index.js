// Month-end reconciliation: invoices from the ledger database, matched by a model.
const { Client } = require('pg');
const Anthropic = require('@anthropic-ai/sdk');

const anthropic = new Anthropic();

async function reconcile(month) {
  const db = new Client({ connectionString: process.env.DATABASE_URL });
  await db.connect();
  try {
    const { rows } = await db.query(
      'SELECT invoice_id, supplier, amount, po_number FROM invoices WHERE period = $1',
      [month],
    );
    const answer = await anthropic.messages.create({
      model: process.env.RECONCILE_MODEL,
      max_tokens: 3000,
      messages: [{ role: 'user', content: `Match these invoices to purchase orders:\n${JSON.stringify(rows)}` }],
    });
    process.stdout.write(`${answer.content[0].text}\n`);
  } finally {
    await db.end();
  }
}

const flag = process.argv.indexOf('--month');
reconcile(flag === -1 ? 'current' : process.argv[flag + 1]);
