package pkcs11

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/asn1"
	"io"
	"math/big"

	"fmt"

	"github.com/miekg/pkcs11"
)

type dsaSignature struct {
	R, S *big.Int
}

type ecdsaSignature dsaSignature

// A PrivateKey represents an RSA key
type PrivateKey struct {
	ctx           *pkcs11.Ctx
	sessionHandle pkcs11.SessionHandle
	ckaId         []byte
}

// New returns a new private key object
func InitPrivateKey(p *pkcs11.Ctx, s pkcs11.SessionHandle, ckaId []byte) (*PrivateKey, error) {
	return &PrivateKey{
		ctx:           p,
		sessionHandle: s,
		ckaId:         ckaId,
	}, nil
}

// Public returns the public key corresponding to priv.
func (priv *PrivateKey) Public() crypto.PublicKey {
	// Get public key from the HSM
	publicKey, err := GetPublic(priv.ctx, priv.sessionHandle, priv.ckaId)
	if err != nil {
		return nil
	}

	return publicKey
}

// Sign delegates the signing of 'msg' to the PKCS11 library.
func (priv *PrivateKey) Sign(rand io.Reader, msg []byte, opts crypto.SignerOpts) (sig []byte, err error) {
	var mechanism *pkcs11.Mechanism
	var orgMsg = make([]byte, len(msg))

	// Copy original message so we can verify RSA signature
	copy(orgMsg, msg)

	// Get the public key corresponding to this private key
	publicKey := priv.Public()
	if publicKey == nil {
		err = fmt.Errorf("Public key of signing private key not found")
		return
	}

	// Pre Signing
	switch publicKey.(type) {
	case *rsa.PublicKey:
		mechanism = pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS, nil)

		// DigestInfo (PKCS1v15)
		msg = append(hashPrefixes[opts.HashFunc()], msg...)
	case *ecdsa.PublicKey:
		mechanism = pkcs11.NewMechanism(pkcs11.CKM_ECDSA, nil)
	default:
		err = fmt.Errorf("Only RSA and ECDSA keys are supported")
	}

	if err != nil {
		return
	}

	// Get the key identifier based on the CKA_ID
	keyId, err := getKeyId(priv.ctx, priv.sessionHandle, priv.ckaId)
	if err != nil {
		return
	}

	// Signing Initiation
	err = priv.ctx.SignInit(priv.sessionHandle, []*pkcs11.Mechanism{mechanism}, keyId)
	if err != nil {
		err = fmt.Errorf("Signing Initiation failed (%s)", err.Error())
		return
	}

	// Sign 'msg'
	sig, err = priv.ctx.Sign(priv.sessionHandle, msg)
	if err != nil {
		err = fmt.Errorf("Signing failed (%s)", err.Error())
		return
	}

	// Post Signing
	switch pub := publicKey.(type) {
	case *rsa.PublicKey:
		if rsa.VerifyPKCS1v15(pub, opts.HashFunc(), orgMsg, sig) != nil {
			err = fmt.Errorf("Invalid RSA signature")
			return
		}

	case *ecdsa.PublicKey:
		// Marshal ECDSA signature
		r := new(big.Int).SetBytes(sig[:len(sig)/2])
		s := new(big.Int).SetBytes(sig[len(sig)/2:])

		if !ecdsa.Verify(pub, msg, r, s) {
			err = fmt.Errorf("Invalid ECDSA signature")
			return
		}

		sig, err = asn1.Marshal(ecdsaSignature{r, s})
		if err != nil {
			return
		}
	}

	return
}
