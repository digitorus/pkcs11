package pkcs11

import (
	"encoding/asn1"
	"math/big"

	"fmt"

	"github.com/miekg/pkcs11"
)

type Key struct {
	Type    string
	Label   string
	CKAID   string
	Public  PublicKeyTemplate
	Private PrivateKeyTemplate
}

type PublicKeyTemplate struct {
	Token       bool
	Encrypt     bool
	Verify      bool
	Wrap        bool
	ModulesBits int
	Exponent    *big.Int
	Curve       string
}

type PrivateKeyTemplate struct {
	Token       bool
	Private     bool
	Subject     string
	Sensitive   bool
	Extractable bool
	Decrypt     bool
	Sign        bool
	Unwrap      bool
}

func CreateKey(p *pkcs11.Ctx, s pkcs11.SessionHandle, k Key) (pub pkcs11.ObjectHandle, priv pkcs11.ObjectHandle, err error) {

	// Key Templates, GenerateKeyPair
	pubTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, k.Public.Encrypt),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, k.Public.Verify),
		pkcs11.NewAttribute(pkcs11.CKA_WRAP, k.Public.Wrap),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, k.Public.Token),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, k.Label),
		pkcs11.NewAttribute(pkcs11.CKA_ID, []byte(k.CKAID)),
	}
	privTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, k.Private.Token),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, k.Private.Private),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, k.Private.Sensitive),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, k.Private.Extractable),
		pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, k.Private.Decrypt),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, k.Private.Sign),
		pkcs11.NewAttribute(pkcs11.CKA_UNWRAP, k.Private.Unwrap),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, k.Label),
		pkcs11.NewAttribute(pkcs11.CKA_ID, []byte(k.CKAID)),
	}

	// Encode ASN.1 key parameters to DER
	var derCurve []byte
	if k.Type == "EC" || k.Type == "ECDSA" {
		derCurve, err = asn1.Marshal(ellipticCurve[k.Public.Curve])
		if err != nil {
			err = fmt.Errorf("error marshalling curve (%s)", err.Error())
			return
		}
	}

	var mechanism *pkcs11.Mechanism
	switch k.Type {
	case "EC":
		mechanism = pkcs11.NewMechanism(pkcs11.CKM_EC_KEY_PAIR_GEN, nil)
		pubTemplate = append(pubTemplate, pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, derCurve))

	case "ECDSA":
		mechanism = pkcs11.NewMechanism(pkcs11.CKM_ECDSA_KEY_PAIR_GEN, nil)
		pubTemplate = append(pubTemplate, pkcs11.NewAttribute(pkcs11.CKA_ECDSA_PARAMS, derCurve))

	case "DH":
		mechanism = pkcs11.NewMechanism(pkcs11.CKM_DH_PKCS_KEY_PAIR_GEN, nil)

	case "DSA":
		mechanism = pkcs11.NewMechanism(pkcs11.CKM_DSA_KEY_PAIR_GEN, nil)

	case "RSA":
		mechanism = pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_KEY_PAIR_GEN, nil)
		pubTemplate = append(pubTemplate, pkcs11.NewAttribute(pkcs11.CKA_MODULUS_BITS, k.Public.ModulesBits))
		pubTemplate = append(pubTemplate, pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, k.Public.Exponent.Bytes()))

	default:
		err = fmt.Errorf("configured key type '%s' is supported", k.Type)
		return
	}

	pub, priv, err = p.GenerateKeyPair(s, []*pkcs11.Mechanism{mechanism}, pubTemplate, privTemplate)
	if err != nil {
		err = fmt.Errorf("generateKeyPair failed (%s)", err.Error())
		return
	}

	return
}
