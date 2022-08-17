//

// Package illuminate_encryption implements the most subset encryption logic of illuminate\encryption  ^v8.51.0
//
// See also
//
// https://github.com/illuminate/encryption
//
package illuminate_encryption

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
)

import (
	"crypto/rand"
	"github.com/forgoer/openssl"
)

type encrypter struct {
	Iv    string `json:"iv"` //base64 encoded
	Mac   string `json:"mac"`
	Value string `json:"value"` //base64 encoded
	key   string
}

func (t *encrypter) UnmarshalJSON(data []byte) error {
	type shadow encrypter
	var tt shadow
	if err := json.Unmarshal(data, &tt); err != nil {
		return err
	}
	if tt.Iv == "" || tt.Value == "" || tt.Mac == "" {
		return errors.New("ticket value is not correct")
	}
	//validMac
	castT := encrypter(tt)
	castT.key = t.key
	e := castT.validMac()
	if e != nil {
		return e
	}
	*t = castT
	return nil
}

func (t *encrypter) MarshalJSON() ([]byte, error) {
	type shadow encrypter
	var tt = shadow(*t)
	tt.Mac = hmacHashSha256(t.Iv+t.Value, t.key)
	t.Mac = tt.Mac
	return json.Marshal(tt)
}

func (t encrypter) validMac() error {
	//validMac
	data := t.Iv + t.Value
	check := validMac(data, t.Mac, t.key)
	if !check {
		return errors.New("ticket mac validation failed")
	}
	return nil
}

//DecryptByte decrypt the given string without unserialization.
func (t *encrypter) DecryptByte() ([]byte, error) {
	//base64 decode iv and value
	ivRaw, err := base64.StdEncoding.DecodeString(t.Iv)
	if err != nil {
		return nil, err
	}
	valueRaw, err := base64.StdEncoding.DecodeString(t.Value)
	if err != nil {
		return nil, err
	}
	//aes decrypt value
	dst, err := openssl.AesCBCDecrypt(valueRaw, []byte(t.key), ivRaw, openssl.PKCS7_PADDING)
	if err != nil {
		return nil, err
	}
	return dst, nil
}

// EncryptByte Encrypt a byte without serialization.
func (t *encrypter) EncryptByte(message []byte) (string, error) {
	iv, err := randomIv()
	if err != nil {
		return "", err
	}
	key := t.key
	//encrypt
	res, err := openssl.AesCBCEncrypt(message, []byte(key), iv, openssl.PKCS7_PADDING)
	if err != nil {
		return "", err
	}
	//base64 encoding
	t.Iv = base64.StdEncoding.EncodeToString(iv)
	t.Value = base64.StdEncoding.EncodeToString(res)
	//marshal the ticket to json byte
	resTicket, err := json.Marshal(t)
	if err != nil {
		return "", err
	}
	//encode the ticket use base64
	ticketR := base64.StdEncoding.EncodeToString(resTicket)

	return ticketR, nil
}

func NewEncrypter(key string) (*encrypter, error) {
	if Supported(key) {
		return &encrypter{key: key}, nil
	}
	return nil, errors.New("input key is not supported")
}

// EncryptString Encrypt a string to without serialization.
func EncryptString(message, key string) (string, error) {
	return EncryptByte([]byte(message), key)
}

// EncryptByte Encrypt a byte without serialization.
func EncryptByte(message []byte, key string) (string, error) {
	t, e := NewEncrypter(key)
	if e != nil {
		return "", e
	}
	return t.EncryptByte(message)
}

// DecryptString Decrypt the given string without unserialization.
func DecryptString(value string, key string) ([]byte, error) {
	//base64 decode
	ticketJsonByte, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return nil, err
	}
	//Unmarshal json  byte
	t, err := NewEncrypter(key)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(ticketJsonByte, &t)
	if err != nil {
		return nil, err
	}

	return t.DecryptByte()
}

// Determine if the MAC for the given payload is valid.
func validMac(message, msgMac, secret string) bool {
	expectedMAC := hmacHashSha256(message, secret)
	return hmac.Equal([]byte(expectedMAC), []byte(msgMac))
}

// Create a MAC for the given value.
func hmacHashSha256(message string, keyString string) string {
	key := []byte(keyString)
	h := hmac.New(sha256.New, key)
	h.Write([]byte(message))
	sha := hex.EncodeToString(h.Sum(nil))
	return sha
}

// Supported Determine if the given key and cipher combination is valid.
func Supported(key string) bool {
	keyLength := len(key)
	return (keyLength == 16) || (keyLength == 32)
}

func randomIv() ([]byte, error) {
	iv := make([]byte, 16)
	_, err := rand.Read(iv)
	if err != nil {
		return nil, err
	}
	return iv, nil
}
