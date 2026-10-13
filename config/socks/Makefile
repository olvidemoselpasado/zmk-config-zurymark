# Comandos del proyecto. Las recetas se indentan con Tab.
BIN      := bin/socksd
PKG      := ./cmd/socksd
FUZZTIME ?= 30s

.PHONY: run test race fuzz lint build build-all try clean

run:
	go run $(PKG)

test:
	go test ./...

race:
	go test -race -count=1 ./...

fuzz:
	go test -run=^$$ -fuzz=FuzzReadRequest -fuzztime=$(FUZZTIME) ./internal/socks5

lint:
	test -z "$$(gofmt -l .)" || (gofmt -l . && false)
	go vet ./...

build:
	CGO_ENABLED=0 go build -o $(BIN) $(PKG)

build-all:
	CGO_ENABLED=0 GOOS=linux   GOARCH=amd64 go build -o bin/socksd-linux-amd64 $(PKG)
	CGO_ENABLED=0 GOOS=linux   GOARCH=arm64 go build -o bin/socksd-linux-arm64 $(PKG)
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o bin/socksd-windows-amd64.exe $(PKG)
	CGO_ENABLED=0 GOOS=darwin  GOARCH=arm64 go build -o bin/socksd-darwin-arm64 $(PKG)

# Con el proxy corriendo (make run), en otra terminal:
try:
	curl -sS --proxy socks5h://127.0.0.1:1080 http://example.com -o /dev/null -w "%{http_code}\n"

clean:
	rm -rf bin
