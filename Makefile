.PHONY: all test lint fmt clean

all: test

test:
	go test -v -race ./...

lint:
	golangci-lint run --config=.github/golangci.yml

fmt:
	gofmt -s -w .
	goimports -w -local github.com/craftedsignal/sigma-parser .

clean:
	go clean -testcache

benchmark:
	go test -bench=. -benchmem ./...

fuzz:
	go test -fuzz FuzzSigmaParser -fuzztime 30s

coverage:
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
