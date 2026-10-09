---
type: fixed
issue: 918
---
#### `explain` answers for `SEM-LLM-NOT-ANALYZED` and describes `CRED-002` as the private key finding `secure` reports (#918)

- `hackmyagent explain SEM-LLM-NOT-ANALYZED` printed "Unknown check ID" and
  exited 1, while `secure --deep` reports that id and exits 2 on it. It now
  exits 0 and explains both records filed under the id: "Deep analysis did
  not run", once for the run when the deep analysis tier could not run, and
  "Deep analysis did not complete for this file", for each file whose answer
  could not be read, with the exit code and the fix.
- `hackmyagent explain CRED-002` described an OpenAI API key, while `secure`
  reports `CRED-002` as a private key file: a `.key` file, a `.pem` file
  holding a private key, or a JSON file whose field value holds one. It now
  describes that finding and gives its fix: move the key out of the
  repository, and if it was committed, rotate it and run `git rm --cached`.
