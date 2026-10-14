# SWS Vault

SWS Vault is an independent Go service for encrypted credential storage and bound use by reference. It is separate from VPS-Commander.

## Development status

This branch implements the v1 core in milestones M1–M8. It is a development deliverable only; no deployment has been performed. Review `docs/security.md` and `docs/ops.md` before any future deployment. Use only fake values during development.

## Build and test

```sh
export PATH=/usr/local/go/bin:$PATH
go build -trimpath -o /tmp/swsvault ./cmd/swsvault
/tmp/swsvault version
go test ./...
go test -race ./...
```

## Local setup

Use a temporary directory so the smoke test never touches `/etc` or `/var/lib`:

```sh
export SWSV_DATA_DIR="$(mktemp -d)"
export SWSV_LISTEN=127.0.0.1:9531
/tmp/swsvault keygen --out "$SWSV_DATA_DIR/master.key"
/tmp/swsvault admin init
/tmp/swsvault serve
```

`admin init` prompts for a password twice and prints a one-time `otpauth://` enrollment URI. Register it in a TOTP app. Open `http://127.0.0.1:9531/admin/login` and sign in. Use fake development values such as `SENTINEL-VALUE-7f3a9c` when testing.

In a second terminal, point the CLI at the same temporary directory and create a client:

```sh
export SWSV_DATA_DIR="/path/to/the/same/temp-dir"
/tmp/swsvault client create --ns demo --name local-test --scopes secrets:list,secrets:write,fetch,resolve,intents:create
# Copy the one-time token into a protected environment injection, not a command argument.
read -rsp 'SWSV_TOKEN: ' SWSV_TOKEN; export SWSV_TOKEN; echo
export SWSV_URL=http://127.0.0.1:9531
export SWSV_NS=demo
```

In the admin panel, create a secret with a host allowlist and the required binding flags. Enable “保存前验证” where the provider supports verification. For a local-only fake test target, use an explicit host such as `127.0.0.1:8080` and enable private/HTTP only for that test binding. A fetch request uses the reference, not the value:

```sh
curl -sS -H "Authorization: Bearer $SWSV_TOKEN" -H 'Content-Type: application/json' \
  -d '{"secret":"vault:demo/SECRET_ID","method":"GET","url":"http://127.0.0.1:8080/"}' \
  "$SWSV_URL/v1/fetch"
```

The example ID and target are placeholders; the bound host must match exactly. Never enable private/HTTP access on an untrusted or production credential.

## REST, MCP, and CLI examples

- REST: `GET /v1/secrets?ns=demo` lists metadata; `POST /v1/secrets` accepts a value in the JSON request body and returns metadata only.
- MCP: POST JSON-RPC `tools/list` to `/mcp` to discover `vault_list`, `vault_fetch`, and `vault_intent`. Tool calls reuse REST scope checks.
- CLI capture: `printf %s 'SENTINEL-VALUE-7f3a9c' | /tmp/swsvault capture --ns demo --label fake --provider generic` reads from stdin and prints only ID/preview.
- CLI run: `/tmp/swsvault run --env API_TOKEN=vault:demo/SECRET_ID -- command args` resolves a reference, passes the value only in the child environment, and redacts child output.
- Git credential: configure `swsvault git-credential` as Git's credential helper; `get` matches explicit host bindings for GitHub/Gitea credentials, while `store` and `erase` are no-ops.

For endpoint and CLI details see `docs/api.md`; for provider templates see `docs/providers.md`; for the threat model see `docs/security.md`; for operational precautions see `docs/ops.md`.
