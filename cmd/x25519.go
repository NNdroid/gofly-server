package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"golang.org/x/crypto/curve25519"
)

type X25519Data struct {
	PrivateKey string
	PublicKey  string
}

// copy from https://github.com/XTLS/Xray-core/blob/a45c343b89e27cc960ea1f7f011a05df047e15d0/main/commands/all/x25519.go#L30C55-L30C55
func executeX25519() (string, error) {
	var err error
	var privateKey []byte
	var publicKey []byte

	//if len(*input_base64) > 0 {
	//	privateKey, err = base64.RawURLEncoding.DecodeString(*input_base64)
	//	if err != nil {
	//		output = err.Error()
	//		goto out
	//	}
	//	if len(privateKey) != curve25519.ScalarSize {
	//		output = "Invalid length of private key."
	//		goto out
	//	}
	//}

	if privateKey == nil {
		privateKey = make([]byte, curve25519.ScalarSize)
		if _, err = rand.Read(privateKey); err != nil {
			return "", err
		}
	}

	// Modify random bytes using algorithm described at:
	// https://cr.yp.to/ecdh.html.
	privateKey[0] &= 248
	privateKey[31] &= 127
	privateKey[31] |= 64

	if publicKey, err = curve25519.X25519(privateKey, curve25519.Basepoint); err != nil {
		return "", err
	}

	bts, err := json.Marshal(
		X25519Data{
			PublicKey:  base64.RawURLEncoding.EncodeToString(publicKey),
			PrivateKey: base64.RawURLEncoding.EncodeToString(privateKey),
		},
	)

	if err != nil {
		return "", err
	}

	return string(bts), nil
}
