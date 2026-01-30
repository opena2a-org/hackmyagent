// Clean project with no security issues
// API keys loaded from environment variables (not hardcoded)

const apiKey = process.env.API_KEY;

module.exports = {
  getApiKey: () => apiKey,
  greet: (name) => `Hello, ${name}!`
};
