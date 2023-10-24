package pkcs11

import (
	"crypto"
	"encoding/asn1"

	"github.com/miekg/pkcs11"
)

// https://golang.org/src/pkg/crypto/rsa/pkcs1v15.go
var hashPrefixes = map[crypto.Hash][]byte{
	crypto.MD5:       {0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x05, 0x05, 0x00, 0x04, 0x10},
	crypto.SHA1:      {0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14},
	crypto.SHA224:    {0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05, 0x00, 0x04, 0x1c},
	crypto.SHA256:    {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20},
	crypto.SHA384:    {0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30},
	crypto.SHA512:    {0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40},
	crypto.MD5SHA1:   {}, // A special TLS case which doesn't use an ASN1 prefix.
	crypto.RIPEMD160: {0x30, 0x20, 0x30, 0x08, 0x06, 0x06, 0x28, 0xcf, 0x06, 0x03, 0x00, 0x31, 0x04, 0x14},
}

var ellipticCurve = map[string]asn1.ObjectIdentifier{
	"secp192r1": {1, 2, 840, 10045, 3, 1, 1},
	"secp224r1": {1, 3, 132, 0, 33},
	"secp256r1": {1, 2, 840, 10045, 3, 1, 7},
	"secp384r1": {1, 3, 132, 0, 34},
	"secp521r1": {1, 3, 132, 0, 35},

	"brainpoolP160r1": {1, 3, 36, 3, 3, 2, 8, 1, 1, 1},
	"brainpoolP192r1": {1, 3, 36, 3, 3, 2, 8, 1, 1, 3},
	"brainpoolP224r1": {1, 3, 36, 3, 3, 2, 8, 1, 1, 5},
	"brainpoolP256r1": {1, 3, 36, 3, 3, 2, 8, 1, 1, 7},
	"brainpoolP320r1": {1, 3, 36, 3, 3, 2, 8, 1, 1, 9},
	"brainpoolP384r1": {1, 3, 36, 3, 3, 2, 8, 1, 1, 11},
	"brainpoolP512r1": {1, 3, 36, 3, 3, 2, 8, 1, 1, 13},
}

var objectType = map[int]string{
	pkcs11.CKO_DATA:              "CKO_DATA",
	pkcs11.CKO_CERTIFICATE:       "CKO_CERTIFICATE",
	pkcs11.CKO_PUBLIC_KEY:        "CKO_PUBLIC_KEY",
	pkcs11.CKO_PRIVATE_KEY:       "CKO_PRIVATE_KEY",
	pkcs11.CKO_SECRET_KEY:        "CKO_SECRET_KEY",
	pkcs11.CKO_HW_FEATURE:        "CKO_HW_FEATURE",
	pkcs11.CKO_DOMAIN_PARAMETERS: "CKO_DOMAIN_PARAMETERS",
	pkcs11.CKO_MECHANISM:         "CKO_MECHANISM",
	pkcs11.CKO_OTP_KEY:           "CKO_OTP_KEY",
	pkcs11.CKO_VENDOR_DEFINED:    "CKO_VENDOR_DEFINED",
}

var (
	// 64 bit PKCS11 libraries
	pkcs11Lib64 = []string{
		"/opt/nfast/toolkits/pkcs11/libcknfast-64.so",
		"/opt/softhsm/lib/softhsm/libsofthsm2.so",
		"/usr/lib64/libeTPkcs11.so",
		"/usr/lib/libCryptoki2_64.so",
		"/usr/lunasa/lib/libCryptoki2_64.so",
		"/usr/safenet/lunaclient/lib/libCryptoki2_64.so",
		"/opt/safenet/lunaclient/lib/libCryptoki2_64.so",
		"/opt/safenet/lunaclient/lib/libCryptoki2_64.sl",
	}

	// 32 bit PKCS11 libraries
	pkcs11Lib32 = []string{
		"/opt/nfast/toolkits/pkcs11/libcknfast.so",
		"/usr/lib/libeTPkcs11.so",
		"/usr/lib/libCryptoki2.so",
		"/usr/lib/libeToken.so",
		"/usr/lunasa/lib/libCryptoki2.so",
		"/usr/safenet/lunaclient/lib/libCryptoki2.so",
		"/opt/safenet/lunaclient/lib/libCryptoki2.so",
		"/opt/safenet/lunaclient/lib/libCryptoki2.sl",
	}
)
