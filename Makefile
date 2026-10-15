GO ?= go
VERSION := $(shell git rev-parse --short=12 HEAD)
LDFLAGS := -X main.commit=$(VERSION)

.PHONY: build test
build:
	mkdir -p bin
	$(GO) build -trimpath -ldflags "$(LDFLAGS)" -o bin/swsvault ./cmd/swsvault

test:
	$(GO) test ./...
