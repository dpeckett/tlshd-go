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
	"fmt"

	"github.com/dpeckett/ktls"
	"github.com/dpeckett/ktls/tls"
	"github.com/dpeckett/tlshd-go/internal/keyring"
)

func (h *Handler) handleClientHello(ctx context.Context, params *HandshakeParams) error {
	h.logger.Info("Handling client hello")

	switch params.AuthMode {
	case HandshakeAuthUnauth, HandshakeAuthX509:
		return h.handleClientX509Handshake(ctx, params)
	case HandshakeAuthPSK:
		return fmt.Errorf("TLS PSK is not supported by Go")
	default:
		return fmt.Errorf("unrecognized auth mode: %d", params.AuthMode)
	}
}

func (h *Handler) handleClientX509Handshake(ctx context.Context, params *HandshakeParams) error {
	h.logger.Info("Performing client X.509 TLS handshake")

	tlsConfig := h.tlsConfig.Clone()

	var certPEM, keyPEM []byte
	if params.X509Cert != TLSNoCert {
		var err error
		certPEM, err = keyring.GetCertificate(params.X509Cert)
		if err != nil {
			return fmt.Errorf("failed to get certificate: %w", err)
		}
	}

	if params.X509PrivKey != TLSNoPrivKey {
		var err error
		keyPEM, err = keyring.GetPrivateKey(params.X509PrivKey)
		if err != nil {
			return fmt.Errorf("failed to get private key: %w", err)
		}
	}

	if len(certPEM) > 0 && len(keyPEM) > 0 {
		clientCert, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			return fmt.Errorf("failed to create X.509 key pair: %w", err)
		}

		tlsConfig.Certificates = []tls.Certificate{clientCert}
	}

	// ServerName is required for SNI (Server Name Indication).
	tlsConfig.ServerName = params.PeerName

	tlsConn := tls.Client(params.Conn, tlsConfig)

	handshakeCtx := ctx
	if params.Timeout > 0 {
		var cancel context.CancelFunc
		handshakeCtx, cancel = context.WithTimeout(ctx, params.Timeout)
		defer cancel()
	}

	if err := tlsConn.HandshakeContext(handshakeCtx); err != nil {
		return fmt.Errorf("TLS handshake failed: %w", err)
	}

	h.logger.Info("TLS handshake complete")

	state := tlsConn.ConnectionState()
	for i, cert := range state.PeerCertificates {
		// The kernel only supports 10 certificates in the chain.
		if i >= 10 {
			h.logger.Warn("Peer certificate chain truncated, more than 10 certificates")
			break
		}

		remotePeerID, err := keyring.CreateCertificate(cert, params.PeerName)
		if err != nil {
			return fmt.Errorf("failed to create certificate: %w", err)
		}

		params.RemotePeerIDs = append(params.RemotePeerIDs, remotePeerID)
	}

	h.logger.Info("Enabling kernel TLS")

	if err := ktls.Enable(tlsConn); err != nil {
		h.logger.Error("Failed to enable kernel TLS", "error", err)

		return fmt.Errorf("failed to enable kernel TLS: %w", err)
	}

	return nil
}
