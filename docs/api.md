# SWS Vault API

All JSON endpoints are served over the configured listener. The default listener is loopback. Client requests use `Authorization: Bearer swsv_<fake-token>`; clients are scoped to one namespace. Error bodies contain generic messages and never echo request values.

## Client endpoints

- `GET /v1/secrets?ns=<namespace>` — list metadata only; a different namespace returns 404.
- `POST /v1/secrets` — write a secret. JSON fields: `ns` (optional; defaults to client namespace), `label`, `provider`, `type`, `value`, optional `username`, and `bindings`. Requires `secrets:write`; response contains metadata only.
- `PUT /v1/secrets/<id>/value` — replace a secret value; requires `secrets:write`.
- `POST /v1/generate` — create a random secret from a selected character set. Fields: `label`, `provider`, `type`, `length` (16–4096), optional `charset`, and `bindings`. Only metadata is returned.
- `POST /v1/resolve` — the one intentional plaintext-returning API. Requires `resolve` and `bindings.allow_resolve=true`; response is marked `Cache-Control: no-store`.
- `POST /v1/intents` — creates a 10-minute token whose digest is stored. The current web submission flow is not yet complete.
- `POST /v1/fetch` — reserved for outbound bound credential injection; currently returns 501 until the hardened fetch engine is implemented.
- `/mcp` — JSON-RPC subset with `initialize` and `tools/list`; tool calls remain incomplete.

## Metadata

Metadata includes ID, namespace, label, provider, type, masked preview, keyed fingerprint, binding policy, timestamps, and status. Secret values are not part of list or write responses.

## Errors

- 400 invalid request
- 401 missing, invalid, expired, or disabled client
- 403 insufficient scope or source IP not allowed
- 404 missing resource or namespace mismatch
- 429 per-client rate limit exceeded

## v1 delivery notes

Implementation and test status will be recorded here as milestones complete. This is a development build, not a production deployment; see `docs/security.md` for known limitations.
