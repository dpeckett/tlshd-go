# tlshd-go

A Linux kernel TLS handshake daemon written in Go. Given we are offloading TLS handshakes to user-space anyway, we might as well perform them using a memory-safe language.

Right now tlshd-go is a very experimental proof of concept and only supports X.509 based client handshakes.

## Building

You'll need the excellent [Earthly](https://earthly.dev/) build tool to build this project.

```bash
earthly +build
```

## Running

You'll need to run the TLS handshake daemon as root.

```bash
sudo ./dist/tlshd-go-linux-amd64
```