.PHONY: build build-xcaddy test-server test vet tidy lint clean docker

BINARY  := caddy-mcp
MODULE  := github.com/venkatkrishna07/caddy-mcp

build:
	go build -o caddy ./cmd/caddy-mcp/

build-xcaddy:
	xcaddy build --with $(MODULE)=./

test-server:
	go build -o test-mcp-server ./cmd/test-mcp-server/

test:
	CGO_ENABLED=1 go test ./... -timeout 120s -race

vet:
	go vet ./...

tidy:
	go mod tidy

lint: vet
	@which staticcheck >/dev/null 2>&1 \
		&& staticcheck ./... \
		|| echo "staticcheck not installed — run: go install honnef.co/go/tools/cmd/staticcheck@latest"

clean:
	rm -f caddy test-mcp-server $(BINARY)

docker:
	docker build -t caddy-mcp .
