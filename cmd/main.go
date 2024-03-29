// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2023 Oracle and/or its affiliates.
 * Copyright (c) 2024 Damian Peckett <damian@pecke.tt>.
 *
 * tlshd-go is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; version 2.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

package main

import (
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/dpeckett/ktls/tls"
	"github.com/dpeckett/tlshd-go/internal/handshake"
	"github.com/urfave/cli/v2"
)

var tlsVersionMap = map[string]uint16{
	"1.2": tls.VersionTLS12,
	"1.3": tls.VersionTLS13,
}

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	app := &cli.App{
		Name:  "tlshd-go",
		Usage: "A Linux kernel TLS handshake daemon",
		Flags: []cli.Flag{
			&cli.GenericFlag{
				Name:    "log-level",
				Aliases: []string{"l"},
				Usage:   "Set the log level",
				Value:   fromLogLevel(slog.LevelInfo),
			},
			&cli.StringFlag{
				Name:  "min-version",
				Usage: "The minimum supported TLS version",
				Value: "1.3",
			},
			&cli.StringSliceFlag{
				Name:  "ca",
				Usage: "The path to a PEM encoded CA certificate file",
			},
		},
		Before: func(c *cli.Context) error {
			logger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
				Level: (*slog.Level)(c.Generic("log-level").(*logLevelFlag)),
			}))
			return nil
		},
		Action: func(c *cli.Context) error {
			minVersion, ok := tlsVersionMap[c.String("min-version")]
			if !ok {
				return fmt.Errorf("unsupported TLS version: %s", c.String("min-version"))
			}

			var rootCAs *x509.CertPool
			if caFiles := c.StringSlice("ca"); len(caFiles) > 0 {
				rootCAs = x509.NewCertPool()

				for _, caFile := range caFiles {
					pem, err := os.ReadFile(caFile)
					if err != nil {
						return fmt.Errorf("failed to read CA file: %w", err)
					}

					if !rootCAs.AppendCertsFromPEM(pem) {
						return fmt.Errorf("failed to append certificates from PEM: %s", caFile)
					}
				}
			}

			tlsConfig := &tls.Config{
				MinVersion: minVersion,
				RootCAs:    rootCAs,
				CipherSuites: []uint16{
					// A secure subset of TLS 1.2 ciphers suites supported by the Linux kernel.
					tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
					// Customizing TLS 1.3 ciphers is not supported: https://github.com/golang/go/issues/29349
					// This is fine as all the ciphers have excellent security properties and are supported by the Linux kernel.
				},
			}

			h := handshake.NewHandler(logger, tlsConfig)

			conn, _, err := handshake.NewNetlinkConn()
			if err != nil {
				logger.Error("Failed to open netlink connection", "error", err)
				return err
			}
			defer conn.Close()

			logger.Info("Listening for TLS handshake requests")

			term := make(chan os.Signal, 1)
			signal.Notify(term, os.Interrupt, syscall.SIGTERM)

			for {
				select {
				case <-term:
					return nil
				default:
					if err := conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
						return fmt.Errorf("failed to set read deadline: %w", err)
					}

					msgs, _, err := conn.Receive()
					if err != nil {
						if errors.Is(err, os.ErrDeadlineExceeded) {
							continue
						}

						return fmt.Errorf("failed to receive netlink messages: %w", err)
					}

					for _, msg := range msgs {
						go func() {
							if err := h.Handle(c.Context, &msg); err != nil {
								logger.Error("Failed to handle handshake message", "error", err)
							}
						}()
					}
				}
			}
		},
	}

	if err := app.Run(os.Args); err != nil {
		logger.Error("Failed to run application", "error", err)
		os.Exit(1)
	}
}

type logLevelFlag slog.Level

func fromLogLevel(l slog.Level) *logLevelFlag {
	f := logLevelFlag(l)
	return &f
}

func (f *logLevelFlag) Set(value string) error {
	return (*slog.Level)(f).UnmarshalText([]byte(value))
}

func (f *logLevelFlag) String() string {
	return (*slog.Level)(f).String()
}
