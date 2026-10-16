# hr-onboarding-assistant

People Operations assistant that drafts offer letters and onboarding checklists
from a new hire's HRIS record. The record carries personal data: legal name,
home address, date of birth, national ID number and salary band.

The project is set up for Cursor (`.cursorrules`) and starts three MCP servers
from `mcp.json`: Google Drive, Slack and a filesystem server over the HRIS
exports.
