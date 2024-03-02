VERSION 0.7
FROM golang:1.22-bookworm
WORKDIR /workspace

all:
  COPY (+build/tlshd-go --GOARCH=amd64) ./dist/tlshd-go-linux-amd64
  COPY (+build/tlshd-go --GOARCH=arm64) ./dist/tlshd-go-linux-arm64

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
  RUN golangci-lint run --timeout=5m --skip-dirs=internal/tls ./...

test:
  COPY . ./
  RUN go test -coverprofile=coverage.out -v ./...
  SAVE ARTIFACT ./coverage.out AS LOCAL coverage.out

# Golang's crypto/tls package does not expose a method for extracting the
# TLS key material from a connection. The following vendors the crypto/tls
# package and applies a couple small patches to build it out of tree and
# to add a method for getting the TLS key material. This could be deprecated
# in the future if kTLS support is merged upstream:
# https://github.com/golang/go/issues/44506
vendor:
  RUN apt update
  RUN apt install -y patch
  ARG GO_VERSION=1.22
  GIT CLONE --branch=release-branch.go${GO_VERSION} https://github.com/golang/go.git go
  WORKDIR go/src/crypto/tls
  RUN rm -rf fipsonly link_test.go example_test.go boring*
  COPY patches patches
  RUN for p in patches/*.diff; do patch -p1 < $p; done && rm -rf patches
  SAVE ARTIFACT . AS LOCAL internal/tls
  SAVE ARTIFACT /workspace/go/LICENSE AS LOCAL internal/tls/LICENSE
