# Provider templates

| Provider | Injected request headers | Default allowed host | Verification endpoint |
|---|---|---|---|
| `cloudflare-token` | `Authorization: Bearer {v}` | `api.cloudflare.com` | `GET https://api.cloudflare.com/client/v4/user/tokens/verify` |
| `cloudflare-global-key` | `X-Auth-Email: {username}`, `X-Auth-Key: {v}` | `api.cloudflare.com` | `GET https://api.cloudflare.com/client/v4/user` |
| `github-pat` | `Authorization: Bearer {v}` | `api.github.com` | `GET https://api.github.com/user` |
| `gitea-token` | `Authorization: token {v}` | Binding must explicitly allow the Gitea host | `GET {base_url}/api/v1/user` |
| `generic` | Explicit header templates using `{v}` and `{username}` | Must be explicitly bound | Optional manually entered URL |

Host names are matched exactly. Wildcards are not supported. Non-default ports must be explicitly present in the host binding. HTTPS is mandatory unless the binding explicitly sets `allow_http`. Private address access is disabled unless `allow_private` is explicitly enabled; known metadata IPs remain blocked. DNS is resolved before dialing and the selected IP is pinned for the connection. Redirects are returned to the caller rather than followed.

The admin panel can verify a provider before storing or rotating a value. Verification uses the same outbound engine, host allowlist, DNS pinning, timeout, body cap, and redaction rules as `fetch`. Cloudflare API tokens additionally require the JSON `success` field to be true. Verification failure returns only a generic message and HTTP status code, never the provider response body, and the value is not stored.
