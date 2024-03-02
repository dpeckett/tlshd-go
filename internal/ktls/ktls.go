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

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"syscall"
	"unsafe"

	"github.com/dpeckett/tlshd-go/internal/tls"
	"golang.org/x/sys/unix"
)

const (
	TLS_TX = 1 // Set transmit parameters.
	TLS_RX = 2 // Set receive parameters.
)

func Enable(fd int32, tlsConn *tls.Conn) error {
	if err := syscall.SetsockoptString(int(fd), syscall.SOL_TCP, unix.TCP_ULP, "tls"); err != nil {
		return fmt.Errorf("failed to enable kernel TLS: %w", err)
	}

	state := tlsConn.ConnectionState()

	switch state.CipherSuite {
	case tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_AES_128_GCM_SHA256:
		if err := setAESGCM128Info(fd, state, false); err != nil {
			return fmt.Errorf("failed to set transmit crypto info: %w", err)
		}

		if err := setAESGCM128Info(fd, state, true); err != nil {
			return fmt.Errorf("failed to set receive crypto info: %w", err)
		}
	case tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_AES_256_GCM_SHA384:
		if err := setAESGCM256Info(fd, state, false); err != nil {
			return fmt.Errorf("failed to set transmit crypto info: %w", err)
		}

		if err := setAESGCM256Info(fd, state, true); err != nil {
			return fmt.Errorf("failed to set receive crypto info: %w", err)
		}
	case tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
		tls.TLS_CHACHA20_POLY1305_SHA256:
		if err := setChaCha20Poly1305Info(fd, state, false); err != nil {
			return fmt.Errorf("failed to set transmit crypto info: %w", err)
		}

		if err := setChaCha20Poly1305Info(fd, state, true); err != nil {
			return fmt.Errorf("failed to set receive crypto info: %w", err)
		}
	default:
		return fmt.Errorf("unsupported cipher suite: %d", state.CipherSuite)
	}

	return nil
}

func setAESGCM128Info(fd int32, state tls.ConnectionState, read bool) error {
	var key, iv, seq []byte
	if read {
		key, iv, seq = state.KeyInfo(true)
	} else {
		key, iv, seq = state.KeyInfo(false)
	}

	info := cryptoInfoAESGCM128{
		Info: cryptoInfo{
			Version:    state.Version,
			CipherType: cipherAESGCM128,
		},
		Key:    [cipherAESGCM128KeySize]byte(key),
		Salt:   [cipherAESGCM128SaltSize]byte(iv[:cipherAESGCM128SaltSize]),
		RecSeq: [cipherAESGCM128RecSeqSize]byte(seq),
	}

	// TLSv1.2 generates IV in the kernel.
	if state.Version == tls.VersionTLS12 {
		info.IV = [cipherAESGCM128IVSize]byte(seq)
	} else {
		copy(info.IV[:], iv[cipherAESGCM128SaltSize:])
	}

	var w bytes.Buffer
	if err := binary.Write(&w, binary.NativeEndian, &info); err != nil {
		return fmt.Errorf("failed to encode crypto info: %w", err)
	}

	level := TLS_TX
	if read {
		level = TLS_RX
	}

	if err := setsockoptBytes(int(fd), unix.SOL_TLS, level, w.Bytes()); err != nil {
		return fmt.Errorf("failed to configure tls socket: %w", err)
	}

	return nil
}

func setAESGCM256Info(fd int32, state tls.ConnectionState, read bool) error {
	var key, iv, seq []byte
	if read {
		key, iv, seq = state.KeyInfo(true)
	} else {
		key, iv, seq = state.KeyInfo(false)
	}

	info := cryptoInfoAESGCM256{
		Info: cryptoInfo{
			Version:    state.Version,
			CipherType: cipherAESGCM256,
		},
		Key:    [cipherAESGCM256KeySize]byte(key),
		Salt:   [cipherAESGCM256SaltSize]byte(iv[:cipherAESGCM256SaltSize]),
		RecSeq: [cipherAESGCM256RecSeqSize]byte(seq),
	}

	// TLSv1.2 generates IV in the kernel.
	if state.Version == tls.VersionTLS12 {
		info.IV = [cipherAESGCM256IVSize]byte(seq)
	} else {
		copy(info.IV[:], iv[cipherAESGCM256SaltSize:])
	}

	var w bytes.Buffer
	if err := binary.Write(&w, binary.NativeEndian, &info); err != nil {
		return fmt.Errorf("failed to encode crypto info: %w", err)
	}

	level := TLS_TX
	if read {
		level = TLS_RX
	}

	if err := setsockoptBytes(int(fd), unix.SOL_TLS, level, w.Bytes()); err != nil {
		return fmt.Errorf("failed to configure tls socket: %w", err)
	}

	return nil
}

func setChaCha20Poly1305Info(fd int32, state tls.ConnectionState, read bool) error {
	var key, iv, seq []byte
	if read {
		key, iv, seq = state.KeyInfo(true)
	} else {
		key, iv, seq = state.KeyInfo(false)
	}

	info := cryptoInfoCHACHA20POLY1305{
		Info: cryptoInfo{
			Version:    state.Version,
			CipherType: cipherCHACHA20POLY1305,
		},
		IV:     [cipherCHACHA20IVSize]byte(iv),
		Key:    [cipherCHACHA20KeySize]byte(key),
		RecSeq: [cipherCHACHA20RecSeqSize]byte(seq),
	}

	var w bytes.Buffer
	if err := binary.Write(&w, binary.NativeEndian, &info); err != nil {
		return fmt.Errorf("failed to encode crypto info: %w", err)
	}

	level := TLS_TX
	if read {
		level = TLS_RX
	}

	if err := setsockoptBytes(int(fd), unix.SOL_TLS, level, w.Bytes()); err != nil {
		return fmt.Errorf("failed to configure tls socket: %w", err)
	}

	return nil
}

func setsockoptBytes(s int, level int, name int, value []byte) error {
	_, _, e1 := syscall.Syscall6(syscall.SYS_SETSOCKOPT, uintptr(s), uintptr(level), uintptr(name), uintptr(unsafe.Pointer(unsafe.SliceData(value))), uintptr(len(value)), 0)
	if e1 != 0 {
		return unix.Errno(e1)
	}

	return nil
}
