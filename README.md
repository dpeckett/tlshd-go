# tlshd-go

A Linux kernel TLS handshake daemon written in Go. Given we are offloading TLS handshakes to user-space anyway, we might as well perform them using a memory-safe language.

## Caveats

* Only supports X.509 based authentication (no support for PSK, see: [#6379](https://github.com/golang/go/issues/6379)).

## Building

You'll need [Earthly](https://earthly.dev/) to build this project.

```bash
earthly +build
```

## Running

```bash
sudo ./dist/tlshd-go-linux-amd64
```