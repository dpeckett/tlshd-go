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

package handshake

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"syscall"
	"time"

	"github.com/dpeckett/ktls/tls"
	"github.com/dpeckett/tlshd-go/internal/keyring"

	"github.com/mdlayher/genetlink"
	"github.com/mdlayher/netlink"
)

// Handler is a handler for the handshake service.
type Handler struct {
	logger    *slog.Logger
	tlsConfig *tls.Config
}

// NewHandler creates a new handshake Handler.
func NewHandler(logger *slog.Logger, tlsConfig *tls.Config) *Handler {
	return &Handler{
		logger:    logger,
		tlsConfig: tlsConfig,
	}
}

// Handle handles a handshake request from the kernel.
func (h *Handler) Handle(ctx context.Context, msg *genetlink.Message) error {
	h.logger.Info("Received handshake request")

	// Is the request valid and intended for the TLS handshake service?
	ad, err := netlink.NewAttributeDecoder(msg.Data)
	if err != nil {
		return fmt.Errorf("failed to create attribute decoder: %w", err)
	}

	tlshdHandshake := false
	for ad.Next() {
		if ad.Type() == HandshakeAAcceptHandlerClass {
			if ad.Uint32() == uint32(HandshakeHandlerClassTLSHD) {
				tlshdHandshake = true
				break
			}
		}
	}

	if err := ad.Err(); err != nil {
		return fmt.Errorf("failed to decode attributes: %w", err)
	}

	if !tlshdHandshake {
		h.logger.Info("Rejected handshake request (not for TLS handshake service)")

		return fmt.Errorf("not for TLS handshake service")
	}

	h.logger.Info("Accepted handshake request")

	// Send an accept message back to the kernel.
	conn, family, err := NewNetlinkConn()
	if err != nil {
		return fmt.Errorf("failed to open netlink connection: %w", err)
	}
	defer conn.Close()

	ae := netlink.NewAttributeEncoder()
	ae.Uint32(HandshakeAAcceptHandlerClass, uint32(HandshakeHandlerClassTLSHD))

	data, err := ae.Encode()
	if err != nil {
		return fmt.Errorf("failed to encode attributes: %w", err)
	}

	acceptMsg := genetlink.Message{
		Header: genetlink.Header{
			Command: HandshakeCmdAccept,
		},
		Data: data,
	}

	// Get the handshake parameters back from the kernel.
	paramMsgs, err := conn.Execute(acceptMsg, family.ID, netlink.Request|netlink.Acknowledge)
	if err != nil {
		return fmt.Errorf("failed to send accept message: %w", err)
	}

	if len(paramMsgs) != 1 {
		return fmt.Errorf("expected one response to the accept message, but got: %d", len(paramMsgs))
	}

	params, err := h.decodeParams(&paramMsgs[0])
	if err != nil {
		return fmt.Errorf("failed to decode handshake parameters: %w", err)
	}

	h.logger.Info("Received handshake parameters", "peerName", params.PeerName)

	switch params.HandshakeType {
	case HandshakeMsgTypeClientHello:
		err = h.handleClientHello(ctx, params)
	case HandshakeMsgTypeServerHello:
		err = h.handleServerHello(ctx, params)
	default:
		err = fmt.Errorf("unrecognized handshake type: %d", params.HandshakeType)
	}

	var sessionStatus uint32
	if err != nil {
		var syscallErr syscall.Errno
		if errors.As(err, &syscallErr) {
			sessionStatus = uint32(syscallErr)
		} else {
			sessionStatus = uint32(syscall.EINVAL)
		}
	}

	// Close our copy of the socket file descriptor (to avoid leaving
	// anything invalid around once the socket is returned to the kernel).
	if err := params.Conn.Close(); err != nil {
		h.logger.Error("Failed to close connection", "error", err)
	}
	params.Conn = nil

	h.logger.Info("Sending handshake done message", "status", sessionStatus)

	// Send a done message and the original socket file descriptor back to the kernel.
	ae = netlink.NewAttributeEncoder()
	ae.Uint32(HandshakeADoneStatus, sessionStatus)
	ae.Int32(HandshakeADoneSockFD, params.SockFD)

	for _, id := range params.RemotePeerIDs {
		ae.Int32(HandshakeADoneRemoteAuth, int32(id))
	}

	data, err = ae.Encode()
	if err != nil {
		return fmt.Errorf("failed to encode attributes: %w", err)
	}

	doneMsg := genetlink.Message{
		Header: genetlink.Header{
			Command: HandshakeCmdDone,
		},
		Data: data,
	}

	_, err = conn.Send(doneMsg, family.ID, netlink.Request)
	if err != nil {
		return fmt.Errorf("failed to send done message: %w", err)
	}

	return nil
}

type HandshakeParams struct {
	PeerName      string
	PeerAddr      net.Addr
	SockFD        int32
	Conn          net.Conn
	HandshakeType HandshakeMsgType
	Timeout       time.Duration
	AuthMode      HandshakeAuth
	X509Cert      keyring.KeySerial
	X509PrivKey   keyring.KeySerial
	PeerIDs       []keyring.KeySerial
	RemotePeerIDs []keyring.KeySerial
}

func (h *Handler) decodeParams(msg *genetlink.Message) (*HandshakeParams, error) {
	ad, err := netlink.NewAttributeDecoder(msg.Data)
	if err != nil {
		return nil, fmt.Errorf("failed to create attribute decoder: %w", err)
	}

	var params HandshakeParams
	for ad.Next() {
		switch ad.Type() {
		case HandshakeAAcceptSockFD:
			params.SockFD = ad.Int32()

			newFD, err := syscall.Dup(int(params.SockFD))
			if err != nil {
				return nil, fmt.Errorf("failed to dup socket fd: %w", err)
			}

			f := os.NewFile(uintptr(newFD), "net")
			if f == nil {
				return nil, fmt.Errorf("failed to create net.Conn from fd: %w", err)
			}
			defer f.Close() // net.FileConn dups the fd, so we can close it here.

			params.Conn, err = net.FileConn(f)
			if err != nil {
				return nil, fmt.Errorf("failed to create net.Conn from fd: %w", err)
			}

			params.PeerAddr = params.Conn.RemoteAddr()
		case HandshakeAAcceptMessageType:
			params.HandshakeType = HandshakeMsgType(ad.Uint32())
		case HandshakeAAcceptPeerName:
			params.PeerName = ad.String()
		case HandshakeAAcceptTimeout:
			params.Timeout = time.Duration(ad.Uint32()) * time.Millisecond
		case HandshakeAAcceptAuthMode:
			params.AuthMode = HandshakeAuth(ad.Uint32())
		case HandshakeAAcceptPeerIdentity:
			params.PeerIDs = append(params.PeerIDs, keyring.KeySerial(ad.Int32()))
		case HandshakeAAcceptCertificate:
			ad.Nested(func(ad *netlink.AttributeDecoder) error {
				for ad.Next() {
					fmt.Println(ad.Type())
					switch ad.Type() {
					case HandshakeAX509Cert:
						params.X509Cert = keyring.KeySerial(ad.Int32())
					case HandshakeAX509PrivKey:
						params.X509PrivKey = keyring.KeySerial(ad.Int32())
					default:
						return fmt.Errorf("unknown certificate attribute type: %d", ad.Type())
					}
				}

				return ad.Err()
			})
		default:
			return nil, fmt.Errorf("unknown attribute type: %d", ad.Type())
		}
	}

	if err := ad.Err(); err != nil {
		return nil, fmt.Errorf("failed to decode attributes: %w", err)
	}

	if params.PeerName == "" {
		names, err := net.LookupAddr(params.PeerAddr.String())
		if err != nil {
			return nil, fmt.Errorf("failed to resolve peer address: %w", err)
		}

		if len(names) == 0 {
			return nil, fmt.Errorf("no names found for peer address")
		}

		// Just use the first name found for now.
		params.PeerName = names[0]
	}

	return &params, nil
}
