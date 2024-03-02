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

const (
	HandshakeFamilyName    = "handshake"
	HandshakeFamilyVersion = 1
	HandshakeMCGroupTLSHD  = "tlshd"
)

type HandshakeHandlerClass int

const (
	HandshakeHandlerClassNone HandshakeHandlerClass = iota
	HandshakeHandlerClassTLSHD
)

type HandshakeMsgType int

const (
	HandshakeMsgTypeUnspec HandshakeMsgType = iota
	HandshakeMsgTypeClientHello
	HandshakeMsgTypeServerHello
)

type HandshakeAuth int

const (
	HandshakeAuthUnspec HandshakeAuth = iota
	HandshakeAuthUnauth
	HandshakeAuthPSK
	HandshakeAuthX509
)

const (
	HandshakeAX509Cert = iota + 1
	HandshakeAX509PrivKey
)

const (
	HandshakeAAcceptSockFD = iota + 1
	HandshakeAAcceptHandlerClass
	HandshakeAAcceptMessageType
	HandshakeAAcceptTimeout
	HandshakeAAcceptAuthMode
	HandshakeAAcceptPeerIdentity
	HandshakeAAcceptCertificate
	HandshakeAAcceptPeerName
)

const (
	HandshakeADoneStatus = iota + 1
	HandshakeADoneSockFD
	HandshakeADoneRemoteAuth
)

const (
	HandshakeCmdReady = iota + 1
	HandshakeCmdAccept
	HandshakeCmdDone
)

const (
	TLSNoCert    = 0
	TLSNoPrivKey = 0
)
