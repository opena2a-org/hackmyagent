---
type: fixed
---
- A2A-002 reports an unauthenticated task submission handler of A2A v0.3.0
  and v1.0. It looked only for `/tasks/send`-style routes, so a `server.ts`
  or `server.py` that handled the `message/send` JSON-RPC method, the
  `SendMessage` method or the `POST /message:send` route with no
  authentication passed. Those handlers are now reported like `/tasks/send`,
  and ones behind authentication still are not.
