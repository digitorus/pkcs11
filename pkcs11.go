package pkcs11

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"math/big"
	"os"

	"fmt"

	"github.com/miekg/pkcs11"
)

type Object struct {
	Type  string
	Id    pkcs11.ObjectHandle
	ckaId []byte
	Value []byte
	Label string
}

func New(module string) *pkcs11.Ctx {
	return pkcs11.New(module)
}

func FindLib(lib string) (file string, err error) {
	// if user provided library, don't search other libs
	if len(lib) > 0 {
		_, err = os.Stat(lib)
		file = lib
		return
	}
	// skip when on 32 bit
	for _, f := range pkcs11Lib64 {
		if _, err = os.Stat(f); err == nil {
			file = f
			return
		}
	}

	// run also on 64 bit, we could have 32 bit drivers
	for _, f := range pkcs11Lib32 {
		if _, err = os.Stat(f); err == nil {
			file = f
			return
		}
	}

	err = errors.New("No PKCS11 libraries found")
	return
}

func getKeyId(p *pkcs11.Ctx, s pkcs11.SessionHandle, ckaId []byte) (keyId pkcs11.ObjectHandle, err error) {
	var objs []Object
	objs, err = GetObjects(p, s, pkcs11.CKO_PRIVATE_KEY, ckaId, 1)
	if err != nil {
		return
	}

	// Check if we found a slot or token
	if len(objs) < 1 {
		err = errors.New("No keys available")
		return
	}

	return objs[0].Id, nil
}

// http://golang.org/src/pkg/crypto/x509/x509.go?#L722
func GetPublic(p *pkcs11.Ctx, s pkcs11.SessionHandle, ckaId []byte) (pub crypto.PublicKey, err error) {
	if len(ckaId) < 1 {
		return nil, fmt.Errorf("Can't select public key without CKA_ID")
	}

	fmt.Printf("Selecting objects with type CKO_PUBLIC_KEY with CKA_ID %x\n", ckaId)

	// find objects
	template := []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_ID, ckaId)}
	err = p.FindObjectsInit(s, template)
	if err != nil {
		fmt.Printf("FindObjectsInit failed (%v)\n", err)
		return
	}
	obj, _, err := p.FindObjects(s, 1)
	if err != nil {
		fmt.Printf("FindObjects failed (%v)\n", err)
		return
	}
	err = p.FindObjectsFinal(s)
	if err != nil {
		fmt.Printf("FindObjectsFinal failed (%v)\n", err)
		return
	}

	// Check if we found a public key
	if len(obj) != 1 {
		err = fmt.Errorf("Found %d public key(s), should have one.", len(obj))
		return
	}

	// Key holders
	var rsaPub rsa.PublicKey
	var ecdsaPub ecdsa.PublicKey

	// Get key type from PKCS#11
	attr, err := p.GetAttributeValue(s, obj[0], []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, nil)})
	if err != nil {
		err = fmt.Errorf("Failed to get public key type (%s)", err.Error())
		return
	}
	// Convert []byte to int
	buf := bytes.NewReader(attr[0].Value)
	kt, err := binary.ReadUvarint(buf)
	if err != nil {
		err = fmt.Errorf("Error converting public key type (%s)", err.Error())
		return
	}
	ktype := int(kt)

	switch ktype {
	case pkcs11.CKK_RSA:
		template = []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_MODULUS, nil),
			pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, nil),
		}
	case pkcs11.CKK_EC:
		template = []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, nil),
			pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, nil),
		}
	default:
		err = fmt.Errorf("Unknown public key type (%v)", ktype)
		return
	}

	// Get public key attributes from PKCS#11
	attr, err = p.GetAttributeValue(s, obj[0], template)
	if err != nil {
		err = fmt.Errorf("Failed to get public key attributes (%s)", err.Error())
		return
	}

	for _, a := range attr {
		// RSA
		if a.Type == pkcs11.CKA_MODULUS {
			n := new(big.Int)
			n.SetBytes(a.Value)
			rsaPub.N = n
		}
		if a.Type == pkcs11.CKA_PUBLIC_EXPONENT {
			e := new(big.Int)
			e.SetBytes(a.Value)
			rsaPub.E = int(e.Int64())
		}
		// ECDSA
		if a.Type == pkcs11.CKA_EC_PARAMS {
			var params asn1.ObjectIdentifier
			_, err = asn1.Unmarshal(a.Value, &params)
			if err != nil {
				err = fmt.Errorf("Failed to decode ASN.1 encoded CKA_EC_PARAMS (%s)", err.Error())
				return
			}
			// P224
			if params.Equal(ellipticCurve["secp224r1"]) {
				ecdsaPub.Curve = elliptic.P224()
			}
			// P256
			if params.Equal(ellipticCurve["secp256r1"]) {
				ecdsaPub.Curve = elliptic.P256()
			}
			// P384
			if params.Equal(ellipticCurve["secp384r1"]) {
				ecdsaPub.Curve = elliptic.P384()
			}
			// P521
			if params.Equal(ellipticCurve["secp521r1"]) {
				ecdsaPub.Curve = elliptic.P521()
			}
		}
		if a.Type == pkcs11.CKA_EC_POINT {
			var ecp []byte
			_, err = asn1.Unmarshal(a.Value, &ecp)
			if err != nil {
				err = fmt.Errorf("Failed to decode ASN.1 encoded CKA_EC_POINT (%s)", err.Error())
				return
			}
			// A P521 key doesn't meet the check, the IsOnCurve check should be ok
			/*pointLenght := ecdsaPub.Curve.Params().BitSize/8*2 + 1
			if len(ecp) != pointLenght {
				err = fmt.Errorf("ASN.1 decoded CKA_EC_POINT (%d) does not fit used curve (%d)", len(ecp), pointLenght)
				return
			}*/
			ecdsaPub.X, ecdsaPub.Y = elliptic.Unmarshal(ecdsaPub.Curve, ecp)
			if ecdsaPub.X == nil {
				err = fmt.Errorf("Failed to decode CKA_EC_POINT")
				return
			}
			if !ecdsaPub.Curve.IsOnCurve(ecdsaPub.X, ecdsaPub.Y) {
				err = fmt.Errorf("Public key is not on Curve")
				return
			}
		}
	}

	switch ktype {
	case pkcs11.CKK_RSA:
		pub = &rsaPub
	case pkcs11.CKK_EC:
		pub = &ecdsaPub
	}
	return
}

func GetObjects(p *pkcs11.Ctx, s pkcs11.SessionHandle, ot interface{}, ckaId []byte, limit int) (objs []Object, err error) {
	// If we want to select a type, this should be uint
	t, usetType := ot.(uint)

	if usetType && len(ckaId) > 0 {
		fmt.Printf("Selecting objects of type %s with CKA_ID %x\n", objectType[t], ckaId)
	} else if len(ckaId) > 0 {
		fmt.Printf("Selecting objects with CKA_ID %x\n", ckaId)
	} else if usetType {
		fmt.Printf("Selecting objects of type %s\n", objectType[t])
	} else {
		fmt.Printf("Selecting all objects\n")
	}

	// find objects
	var template []*pkcs11.Attribute
	if usetType {
		template = append(template, pkcs11.NewAttribute(pkcs11.CKA_CLASS, t))
	}
	if len(ckaId) > 0 {
		template = append(template, pkcs11.NewAttribute(pkcs11.CKA_ID, ckaId))
	}

	err = p.FindObjectsInit(s, template)
	if err != nil {
		fmt.Printf("FindObjectsInit failed (%v)\n", err)
		return
	}
	obj, _, err := p.FindObjects(s, limit)
	if err != nil {
		fmt.Printf("FindObjects failed (%v)\n", err)
		return
	}
	err = p.FindObjectsFinal(s)
	if err != nil {
		fmt.Printf("FindObjectsFinal failed (%v)\n", err)
		return
	}

	// Check if we found something
	if len(obj) < 1 {
		return
	}

	// Get standard object attributes
	template = []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_ID, nil),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, nil),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, nil),
	}

	// We can't request the value of a private key object
	if t == pkcs11.CKO_CERTIFICATE {
		template = append(template, pkcs11.NewAttribute(pkcs11.CKA_VALUE, nil))
	}

	for _, id := range obj {
		attr, err := p.GetAttributeValue(s, id, template)
		if err != nil {
			fmt.Printf("Failed to get attribute value of object %s\n", err.Error())
		}
		var o Object
		o.Id = id
		for _, a := range attr {
			// Each private key object is matched with its corresponding certificate by retrieving
			// their respective CKA_ID attributes. A matching pair must share the same unique CKA_ID.
			if a.Type == pkcs11.CKA_ID {
				o.ckaId = a.Value
			}
			if a.Type == pkcs11.CKA_VALUE {
				o.Value = a.Value
			}
			if a.Type == pkcs11.CKA_LABEL {
				o.Label = string(a.Value)
			}
			if a.Type == pkcs11.CKA_CLASS {
				objClass, _ := binary.Uvarint(a.Value)
				switch uint(objClass) {
				case pkcs11.CKO_PRIVATE_KEY:
					o.Type = "Private"
				case pkcs11.CKO_PUBLIC_KEY:
					o.Type = "Public"
				case pkcs11.CKO_CERTIFICATE:
					o.Type = "Certificate"
				case pkcs11.CKO_SECRET_KEY:
					o.Type = "Secret"
				}
			}
		}

		objs = append(objs, o)
	}

	return
}

func SelectSlot(p *pkcs11.Ctx) (slot uint, err error) {
	fmt.Println("Select a slot available via this library:")

	// Get slots
	slots, err := p.GetSlotList(true)
	if err != nil {
		err = fmt.Errorf("failed to get list of slots (%w)\n", err)
		return
	}

	// No slots available
	if len(slots) < 1 {
		err = errors.New("no slots available")
		return
	}

	// For each slot
	for i, sl := range slots {
		si, err := p.GetTokenInfo(sl)
		if err != nil {
			err = fmt.Errorf("could not retrieve information about token (%v): %w", sl, err)
			return 0, err
		}
		fmt.Printf("[%v] %v (%v)\n", i, si.Label, si.ManufacturerID)
	}

	// Ask to select slot
	/*
		for {
			inp := input.Input{Label: "Slot", Required: true}
			i := inp.Int(0)
			if i < len(slots) {
				slot = slots[i]
				break
			}
		}*/

	return
}

func SlotInfo(p *pkcs11.Ctx, s uint, skipVerify bool) (err error) {
	// Get information about token
	t, err := p.GetTokenInfo(s)
	if err != nil {
		err = fmt.Errorf("Failed to get slot information (%s)\n", err.Error())
		return
	}

	// Enter serial number
	// if !skipVerify && len(t.SerialNumber) > 0 {
	// 	for {
	// 		inp := input.Input{Label: "Enter the device serial number for verification", Required: true}
	// 		if t.SerialNumber != string(inp.String("")) {
	// 			fmt.CPrintln(fmt.Red, "Invalid serial number!")
	// 			continue
	// 		}
	// 		break
	// 	}
	// }

	// Print and log slot details
	fmt.Println("Information about selected slot:")
	if len(t.ManufacturerID) > 0 {
		fmt.Println("\t- ManufacturerID:", t.ManufacturerID)
	}
	if len(t.Model) > 0 {
		fmt.Println("\t- Model:", t.Model)
	}
	if len(t.SerialNumber) > 0 {
		fmt.Println("\t- SerialNumber:", t.SerialNumber)
	}
	fmt.Printf("\t- HardwareVersion: %d.%d\n", t.HardwareVersion.Major, t.HardwareVersion.Minor)
	fmt.Printf("\t- FirmwareVersion: %d.%d\n", t.FirmwareVersion.Major, t.FirmwareVersion.Minor)

	return
}

func CreateSession(p *pkcs11.Ctx, slot uint, pw string, rw bool) (s pkcs11.SessionHandle, err error) {
	// Open Session
	//
	// Possible session options:
	// - CKF_RW_SESSION			| session is r/w
	// - CKF_SERIAL_SESSION		| no parallel
	if rw {
		s, err = p.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
		if err != nil {
			err = fmt.Errorf("opening session with flags CKF_SERIAL_SESSION and CKF_RW_SESSION failed: %v", err.Error())
			return
		}
	} else {
		s, err = p.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION)
		if err != nil {
			err = fmt.Errorf("opening session with flags CKF_SERIAL_SESSION failed: %v", err.Error())
			return
		}
	}

	// Login
	err = p.Login(s, pkcs11.CKU_USER, pw)
	if err != nil {
		err = fmt.Errorf("login with user type CKU_USER failed: %s", err.Error())
		return
	}

	return
}

func GetCert(p *pkcs11.Ctx, s pkcs11.SessionHandle, ckaId []byte) (cert *x509.Certificate, id []byte, err error) {
	var objs []Object
	objs, err = GetObjects(p, s, pkcs11.CKO_CERTIFICATE, ckaId, 25)
	if err != nil {
		return
	}

	// If we have multiple certificates with the same ckaID, ask to select one
	if len(objs) > 1 {
		fmt.Println("Which certificate would you like to use:")

		// For each certificate
		certs := make(map[int]*x509.Certificate, len(objs))
		for i, o := range objs {
			certs[i], err = x509.ParseCertificate(o.Value)
			if err != nil {
				err = fmt.Errorf("error parsing certificate data from PKCS#11: %s", err.Error())
				break
			}
			fmt.Printf("[%d] %x [%s] (%s)\n", i, certs[i].Subject.CommonName, certs[i].SubjectKeyId, certs[i].Issuer.CommonName)
		}

		// Ask to select a certificate
		/*for cert == nil {
			inp := input.Input{Label: "Certificate", Required: true}
			i := inp.Int(0)
			if _, ok := certs[i]; ok {
				cert = certs[i]
			}
		}*/
	} else if len(objs) == 1 {
		id = objs[0].ckaId // set ckaid of returned object
		cert, err = x509.ParseCertificate(objs[0].Value)
		if err != nil {
			err = fmt.Errorf("error parsing certificate data from PKCS#11: %s", err.Error())
			return
		}
	}
	return
}

func ImportCert(p *pkcs11.Ctx, s pkcs11.SessionHandle, cert *x509.Certificate, ckaId []byte, label string) (object pkcs11.ObjectHandle, err error) {
	// Get object attributes (Certificate)
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_CERTIFICATE),

		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_SUBJECT, cert.RawSubject),
		pkcs11.NewAttribute(pkcs11.CKA_ID, ckaId),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, cert.Raw),
		pkcs11.NewAttribute(pkcs11.CKA_CERTIFICATE_TYPE, 0),
	}
	object, err = p.CreateObject(s, template)
	if err != nil {
		err = fmt.Errorf("failed to import certificate: %s", err.Error())
		return
	}
	return
}
