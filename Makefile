VERSION  ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT   ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "none")
BUILD_AT ?= $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
LDFLAGS   = -s -w -X main.Version=$(VERSION) -X main.Commit=$(COMMIT) -X main.BuildAt=$(BUILD_AT)

.PHONY: build build-arm64 test lint clean

build:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags '$(LDFLAGS)' -o build/axcerberus-linux-amd64 ./cmd/axcerberus

build-arm64:
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags '$(LDFLAGS)' -o build/axcerberus-linux-arm64 ./cmd/axcerberus

build-all: build build-arm64

zip: build-all
	@mkdir -p build/axcerberus
	@cp build/axcerberus-linux-amd64 build/axcerberus-linux-arm64 build/axcerberus/
	@cp dist/setup.sh dist/uninstall.sh dist/config.avx build/axcerberus/
	@cp -r dist/hooks dist/rules build/axcerberus/
	@cd build && zip -r axcerberus-v$(VERSION).zip axcerberus/
	@rm -rf build/axcerberus
	@echo "Created: build/axcerberus-v$(VERSION).zip"

test:
	go test ./tests/... -v -count=1

lint:
	golangci-lint run ./...

clean:
	rm -rf build/
