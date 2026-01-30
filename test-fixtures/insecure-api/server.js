const express = require('express');
const config = require('./config.json');

const app = express();

app.get('/health', (req, res) => {
  res.json({ status: 'ok' });
});

app.listen(config.server.port, config.server.host, () => {
  console.log(`Server running on ${config.server.host}:${config.server.port}`);
});
