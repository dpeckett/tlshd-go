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

package keyring_test

import (
	"crypto/x509"
	"testing"

	"github.com/dpeckett/tlshd-go/internal/keyring"
	"github.com/dpeckett/tlshd-go/internal/util"
	"github.com/stretchr/testify/require"
)

func TestCreateCertificate(t *testing.T) {
	cert, err := util.GenerateSelfSignedCert()
	require.NoError(t, err)

	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	require.NoError(t, err)

	serial, err := keyring.CreateCertificate(x509Cert, "localhost")
	require.NoError(t, err)

	require.NotZero(t, serial)
}
