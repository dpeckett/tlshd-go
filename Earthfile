VERSION 0.7
FROM golang:1.22-bookworm
WORKDIR /workspace

all:
  COPY (+build/tlshd-go --GOARCH=amd64) ./dist/tlshd-go-linux-amd64
  COPY (+build/tlshd-go --GOARCH=arm64) ./dist/tlshd-go-linux-arm64
  RUN cd dist && find . -type f -exec sha256sum {} \; >> ../checksums.txt
  SAVE ARTIFACT ./dist/tlshd-go-linux-amd64 AS LOCAL dist/tlshd-go-linux-amd64
  SAVE ARTIFACT ./dist/tlshd-go-linux-arm64 AS LOCAL dist/tlshd-go-linux-arm64
  SAVE ARTIFACT ./checksums.txt AS LOCAL dist/checksums.txt

build:
  ARG GOOS=linux
  ARG GOARCH=amd64
  COPY go.mod go.sum ./
  RUN go mod download
  COPY . .
  RUN CGO_ENABLED=0 go build -o tlshd-go cmd/main.go
  SAVE ARTIFACT ./tlshd-go AS LOCAL dist/tlshd-go-${GOOS}-${GOARCH}

tidy:
  LOCALLY
  RUN go mod tidy
  RUN go fmt ./...

lint:
  FROM golangci/golangci-lint:v1.56.2
  WORKDIR /workspace
  COPY . ./
  RUN golangci-lint run --timeout=5m ./...

test:
  COPY . ./
  # Must be run privileged so we can access the root users keyring.
  RUN --privileged go test -coverprofile=coverage.out -v ./...
  SAVE ARTIFACT ./coverage.out AS LOCAL coverage.out