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

package keyring

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/dpeckett/keyutils"
)

// KeySerial is a unique identifier for a key in the kernel keyring.
type KeySerial int32

// GetCertificate returns the X.509 certificate for the given serial number.
// As of today, this will probably not work as we need to think about how to
// delegate kernel asymmetric keys to user space.
func GetCertificate(serial KeySerial) ([]byte, error) {
	key := keyutils.GetKey(int32(serial))

	certDer, err := key.Get()
	if err != nil {
		return nil, fmt.Errorf("failed to get key value: %w", err)
	}

	pemBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDer,
	}

	return pem.EncodeToMemory(pemBlock), nil
}

// GetPrivateKey returns the private key for the given serial number.
// As of today, this will probably not work as we need to think about how to
// delegate kernel asymmetric keys to user space.
func GetPrivateKey(serial KeySerial) ([]byte, error) {
	key := keyutils.GetKey(int32(serial))

	keyDer, err := key.Get()
	if err != nil {
		return nil, fmt.Errorf("failed to get key value: %w", err)
	}

	pemBlock := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyDer,
	}

	return pem.EncodeToMemory(pemBlock), nil
}

// CreateCertificate creates a key containing the peer's certificate.
func CreateCertificate(cert *x509.Certificate, peerName string) (KeySerial, error) {
	keyring, err := keyutils.UserKeyring()
	if err != nil {
		return 0, fmt.Errorf("failed to get user keyring: %w", err)
	}

	description := fmt.Sprintf("TLS x509 %s", peerName)
	key, err := keyring.AddType(description, "asymmetric", cert.Raw)
	if err != nil {
		return 0, fmt.Errorf("failed to add key: %w", err)
	}

	return KeySerial(key.Id()), nil
}
