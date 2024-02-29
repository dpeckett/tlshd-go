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
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/dpeckett/tlshd-go/handshake"
	"github.com/urfave/cli/v2"
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	app := &cli.App{
		Name:  "tlshd-go",
		Usage: "A Linux kernel TLS handshake daemon written in Go",
		Flags: []cli.Flag{
			&cli.GenericFlag{
				Name:    "log-level",
				Aliases: []string{"l"},
				Usage:   "Set the log level",
				Value:   fromLogLevel(slog.LevelInfo),
			},
		},
		Before: func(c *cli.Context) error {
			logger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
				Level: (*slog.Level)(c.Generic("log-level").(*logLevelFlag)),
			}))
			return nil
		},
		Action: func(c *cli.Context) error {
			// TODO: read the tls configuration from a file.
			tlsConfig := &tls.Config{
				InsecureSkipVerify: true,
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
							if err := h.Handle(&msg); err != nil {
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
