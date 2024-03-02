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

package ktls

const (
	cipherAESGCM128           = 51
	cipherAESGCM128IVSize     = 8
	cipherAESGCM128KeySize    = 16
	cipherAESGCM128SaltSize   = 4
	cipherAESGCM128RecSeqSize = 8

	cipherAESGCM256           = 52
	cipherAESGCM256IVSize     = 8
	cipherAESGCM256KeySize    = 32
	cipherAESGCM256SaltSize   = 4
	cipherAESGCM256RecSeqSize = 8

	cipherCHACHA20POLY1305   = 54
	cipherCHACHA20IVSize     = 12
	cipherCHACHA20KeySize    = 32
	cipherCHACHA20RecSeqSize = 8
)

type cryptoInfo struct {
	Version    uint16
	CipherType uint16
}

type cryptoInfoAESGCM128 struct {
	Info   cryptoInfo
	IV     [cipherAESGCM128IVSize]byte
	Key    [cipherAESGCM128KeySize]byte
	Salt   [cipherAESGCM128SaltSize]byte
	RecSeq [cipherAESGCM128RecSeqSize]byte
}

type cryptoInfoAESGCM256 struct {
	Info   cryptoInfo
	IV     [cipherAESGCM256IVSize]byte
	Key    [cipherAESGCM256KeySize]byte
	Salt   [cipherAESGCM256SaltSize]byte
	RecSeq [cipherAESGCM256RecSeqSize]byte
}

type cryptoInfoCHACHA20POLY1305 struct {
	Info   cryptoInfo
	IV     [cipherCHACHA20IVSize]byte
	Key    [cipherCHACHA20KeySize]byte
	RecSeq [cipherCHACHA20RecSeqSize]byte
}
