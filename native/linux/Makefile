.PHONY: build test

build:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o bin/networkcontrol-linux-amd64 .
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -o bin/networkcontrol-linux-arm64 .

test:
	go test ./...
	go vet ./...
