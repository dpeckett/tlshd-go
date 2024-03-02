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
	"net"
	"time"
)

type KeySerial int32

type HandshakeParams struct {
	PeerName      string
	PeerAddr      net.Addr
	SockFD        int32
	Conn          net.Conn
	HandshakeType HandshakeMsgType
	Timeout       time.Duration
	AuthMode      HandshakeAuth
	X509Cert      KeySerial
	X509PrivKey   KeySerial
	PeerIDs       []KeySerial
	RemotePeerIDs []KeySerial
}
