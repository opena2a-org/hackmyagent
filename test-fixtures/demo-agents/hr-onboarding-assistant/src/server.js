// Drafts an offer letter from the HRIS record posted to /offer-letter.
const fs = require('node:fs');
const path = require('node:path');
const express = require('express');
const OpenAI = require('openai');

const template = fs.readFileSync(path.join(__dirname, '..', 'templates', 'offer-letter.md'), 'utf8');
const openai = new OpenAI();
const app = express();
app.use(express.json());

app.post('/offer-letter', async (req, res) => {
  // The whole record goes to the model: name, home address, date of birth,
  // national ID number and salary band.
  const record = req.body;
  const completion = await openai.chat.completions.create({
    model: process.env.OFFER_MODEL,
    messages: [
      { role: 'system', content: `Fill in this offer letter from the HRIS record.\n\n${template}` },
      { role: 'user', content: JSON.stringify(record) },
    ],
  });
  res.json({ draft: completion.choices[0].message.content });
});

app.listen(Number(process.env.PORT || 4100));
