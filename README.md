# SWS Vault

SWS Vault is an independent Go service for storing credentials encrypted at rest and using them by reference. It is not part of VPS-Commander.

## Current development status

This branch is implementing v1 in milestones M1–M8. Do not use it with production credentials until the full acceptance suite passes and the remaining security controls are complete.

## Local development

```sh
export PATH=/usr/local/go/bin:$PATH
go test ./...
go build ./...
```

Use only fake values such as `SENTINEL-VALUE-7f3a9c` while testing. `swsvault keygen --out ./tmp/master.key` creates a new key file with exclusive creation and restrictive permissions. Keep the key outside version control and separate from the database.

The service defaults to `127.0.0.1:9531`. Runtime configuration is provided by `SWSV_DATA_DIR`, `SWSV_LISTEN`, and `SWSV_PUBLIC_BASE_URL`.
