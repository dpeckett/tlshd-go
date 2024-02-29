# tlshd-go

A Linux kernel TLS handshake daemon written in Go. 

Given we are offloading TLS handshakes to user-space anyway, we might as well perform them using a memory-safe language.

Right now tlshd-go is a very experimental proof of concept and only currently support X.509 based client handshakes. It is not recommended for production use.