BUILDDIR ?= "./bin"
BUILDTIME=$(shell date --rfc-3339=seconds)
GITCOMMITID=$(shell git rev-parse HEAD)
MAINFILE=cmd/main.go
LDFLAGS=-X "github.com/footprintai/go-certs/pkg/version.BuildTime=${BUILDTIME}" -X "github.com/footprintai/go-certs/pkg/version.GitCommitId=${GITCOMMITID}"

tidy: ## Tidy go modules
	./gomodtidy.sh

windows: ## Build for Windows
	env GOOS=windows GOARCH=amd64 CGO_ENABLED=0 \
	go build -ldflags '${LDFLAGS} -extldflags "-static"' -o ${BUILDDIR}/go-certs.windows.exe ${MAINFILE}

linux: ## Build for Linux
	env GOOS=linux GOARCH=amd64 CGO_ENABLED=0 \
    go build -ldflags '${LDFLAGS} -extldflags "-static"' -o ${BUILDDIR}/go-certs.linux ${MAINFILE}

darwin: ## Build for Darwin (macOS)
	env GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 \
    go build -ldflags '${LDFLAGS} -extldflags "-static"' -o ${BUILDDIR}/go-certs.darwin ${MAINFILE}

darwinSilicon: ## Build for Darwin Silicon (macOS M1)
	env GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 \
    go build -ldflags '${LDFLAGS} -extldflags "-static"' -o ${BUILDDIR}/go-certs.darwin-arm64 ${MAINFILE}

build: windows linux darwin darwinSilicon ## Build all platform binaries
	@echo commitid: $(GITCOMMITID)
	@echo buildtime: $(BUILDTIME)

local: ## Build for local development
	mkdir -p ${BUILDDIR}
	go build -ldflags '${LDFLAGS}' -o ${BUILDDIR}/go-certs ${MAINFILE}

test: ## Run tests
	go test -v ./...

clean: ## Clean build artifacts
	go clean
	rm -rf ${BUILDDIR}

run: local ## Run local build
	${BUILDDIR}/go-certs

generate: local ## Run generate command
	${BUILDDIR}/go-certs generate

inspect: local ## Run inspect command
	${BUILDDIR}/go-certs inspect

deps: ## Install dependencies
	go get github.com/spf13/cobra

help: ## Display available commands
	@grep -E '^[a-zA-Z_-]+:.*?## .*$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $1, $2}'

.PHONY: tidy windows linux darwin darwinSilicon build local test clean run generate inspect deps help
