---
type: fixed
issue: 287
---
#### A LOW finding no longer explains itself as critical (#287)

- **Package scans lower test-file and build-file findings to LOW after their guidance is
  written**, so a card could print `LOW` above "Critical in this context because …". The
  demoted finding's guidance now opens with why it is LOW (`LOW here because it is in a test
  file, which is not a runtime attack surface (detected as CRITICAL).`) and keeps the
  analyzer's reason as "In runtime code it would be critical because …".
- **`this unknown` no longer appears in guidance.** An artifact the classifier could not type
  is now named as a file ("because this file may influence agent behavior or data handling").
- Severities, verdicts and scores are unchanged; only guidance text moves.
