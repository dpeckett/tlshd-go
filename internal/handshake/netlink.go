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
	"fmt"

	"github.com/mdlayher/genetlink"
)

// NewNetlinkConn opens a new Netlink connection configured for TLS handshakes.
func NewNetlinkConn() (*genetlink.Conn, *genetlink.Family, error) {
	conn, err := genetlink.Dial(nil)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to dial netlink: %w", err)
	}

	family, err := conn.GetFamily(HandshakeFamilyName)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get family: %w", err)
	}

	var mcgrp uint32
	for _, g := range family.Groups {
		if g.Name == HandshakeMCGroupTLSHD {
			mcgrp = g.ID
			break
		}
	}

	if mcgrp == 0 {
		return nil, nil, fmt.Errorf("failed to find TLSHD multicast group")
	}

	if err := conn.JoinGroup(mcgrp); err != nil {
		return nil, nil, fmt.Errorf("failed to join group: %w", err)
	}

	return conn, &family, nil
}
