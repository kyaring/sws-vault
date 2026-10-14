# SWS Vault

SWS Vault is an independent Go service for encrypted credential storage and bound use by reference. It is separate from VPS-Commander.

## Development status

This branch implements the v1 core in milestones M1–M8. It is not production-ready yet: see the known limitations in `docs/security.md`, especially Argon2id password hashing and the incomplete provider verification/intent flow. Use only fake values during development.

## Build and test

```sh
export PATH=/usr/local/go/bin:$PATH
go build -trimpath -o /tmp/swsvault ./cmd/swsvault
/tmp/swsvault version
go test ./...
```

## Local setup

Use a temporary data directory and keep the master key out of the repository:

```sh
export SWSV_DATA_DIR="$(mktemp -d)"
export SWSV_LISTEN=127.0.0.1:9531
/tmp/swsvault keygen --out "$SWSV_DATA_DIR/master.key"
/tmp/swsvault admin init
/tmp/swsvault serve
```

The `admin init` command prompts for a password and prints a one-time `otpauth://` URI. Register it in a TOTP app. Open `http://127.0.0.1:9531/admin/login` and sign in. Enter only fake development values, such as `SENTINEL-VALUE-7f3a9c`, when testing.

In a second terminal, point the CLI at the same temporary data directory for local administration, or use a client token created by the root-only local command:

```sh
export SWSV_DATA_DIR="/path/to/the/same/temp-dir"
/tmp/swsvault client create --ns demo --name local-test --scopes secrets:list,secrets:write,fetch,resolve,intents:create
export SWSV_URL=http://127.0.0.1:9531
export SWSV_NS=demo
# Set SWSV_TOKEN in the environment to the one-time token printed by client create.
```

The token is displayed only once. Do not paste a real token into shell history or a command argument; prefer a permission-0600 env file or a protected environment injection. `--env-file FILE` is rejected if group/world permission bits are set.

## REST, MCP, and CLI examples

- REST: `GET /v1/secrets?ns=demo` lists metadata; `POST /v1/secrets` accepts the value in a JSON request body and returns metadata only.
- MCP: POST JSON-RPC `tools/list` to `/mcp` to discover `vault_list`, `vault_fetch`, and `vault_intent`. Tool calls reuse the same scope checks as the REST operations.
- CLI capture: `printf %s 'SENTINEL-VALUE-7f3a9c' | /tmp/swsvault capture --ns demo --label fake --provider generic` reads the value from stdin and prints only ID/preview.
- CLI run: `/tmp/swsvault run --env API_TOKEN=vault:demo/SECRET_ID -- command args` resolves a bound reference, passes it only in the child environment, and redacts child output.
- Git credential: configure `swsvault git-credential` as Git's credential helper; `get` matches explicit host bindings for GitHub/Gitea credentials, while `store` and `erase` are no-ops.

For API details see `docs/api.md`; for templates see `docs/providers.md`; for threat model and operational precautions see `docs/security.md` and `docs/ops.md`.
