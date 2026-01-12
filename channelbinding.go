package smb2

import (
	"crypto"
	"crypto/md5"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"net"
)

// ComputeChannelBindingToken computes the MD5 hash of gss_channel_bindings_struct
// for EPA (Extended Protection for Authentication). RFC 5929 tls-server-end-point.
// Returns nil if cert is nil.
func ComputeChannelBindingToken(cert *x509.Certificate) []byte {
	if cert == nil {
		return nil
	}

	certHash := HashCertificate(cert)
	if certHash == nil {
		return nil
	}

	// "tls-server-end-point:" + certificate hash
	appData := append([]byte("tls-server-end-point:"), certHash...)

	// gss_channel_bindings_struct: 5 DWORDs header + application data
	buf := make([]byte, 20+len(appData))
	binary.LittleEndian.PutUint32(buf[16:], uint32(len(appData)))
	copy(buf[20:], appData)

	hash := md5.Sum(buf)
	return hash[:]
}

// HashCertificate computes the certificate hash per RFC 5929 section 4.1.
// Uses SHA-256 by default, SHA-384 for SHA384-based signatures, SHA-512 for SHA512-based signatures.
func HashCertificate(cert *x509.Certificate) []byte {
	if cert == nil {
		return nil
	}

	var h crypto.Hash

	switch cert.SignatureAlgorithm {
	case x509.SHA384WithRSA, x509.SHA384WithRSAPSS, x509.ECDSAWithSHA384:
		h = crypto.SHA384
	case x509.SHA512WithRSA, x509.SHA512WithRSAPSS, x509.ECDSAWithSHA512:
		h = crypto.SHA512
	default:
		// SHA-256 for SHA256-based, MD5, SHA1, and unknown algorithms
		h = crypto.SHA256
	}

	hasher := h.New()
	hasher.Write(cert.Raw)
	return hasher.Sum(nil)
}

// ComputeChannelBindingFromConn extracts certificate from TLS connection and computes token.
// Returns nil if connection is not TLS or has no peer certificates.
func ComputeChannelBindingFromConn(conn net.Conn) []byte {
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return nil
	}

	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil
	}

	return ComputeChannelBindingToken(state.PeerCertificates[0])
}
