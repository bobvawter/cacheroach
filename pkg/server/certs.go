// Copyright 2021 The Cockroach Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"time"

	"github.com/Mandala/go-log"
	"github.com/bobvawter/cacheroach/pkg/server/common"
)

// ProvideCertificates will load the certificate and keys specified and
// can optionally generate a self-signed certificate for debugging.
func ProvideCertificates(cfg *common.Config, log *log.Logger) ([]tls.Certificate, error) {
	if cfg.GenerateSelfSigned {
		log.Warn("using self-signed certificate")
		return generateSelfSigned()
	}

	if cfg.CertBundle == "" {
		log.Trace("not enabling TLS, no certificate bundle")
		return nil, nil
	}
	if cfg.PrivateKey == "" {
		log.Trace("not enabling TLS, no private key")
		return nil, nil
	}

	cert, err := tls.LoadX509KeyPair(cfg.CertBundle, cfg.PrivateKey)
	if err != nil {
		return nil, err
	}
	log.Trace("loaded certificate and key")
	return []tls.Certificate{cert}, nil

}

func generateSelfSigned() ([]tls.Certificate, error) {
	now := time.Now()
	pk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	template := &x509.Certificate{
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:           []net.IP{{127, 0, 0, 1}},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		NotAfter:              now.AddDate(0, 0, 1),
		NotBefore:             now,
		SerialNumber:          big.NewInt(12345),
		Subject:               pkix.Name{Organization: []string{"cacheroach"}},
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, pk.Public(), pk)
	if err != nil {
		return nil, err
	}

	parsed, err := x509.ParseCertificates(der)
	if err != nil {
		return nil, err
	}

	c := tls.Certificate{
		Certificate: [][]byte{parsed[0].Raw},
		PrivateKey:  pk,
		Leaf:        parsed[0],
	}
	return []tls.Certificate{c}, nil

}
