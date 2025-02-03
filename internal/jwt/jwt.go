package jwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"time"
)

type JWTHeader struct {
	Alg string `json:"alg,omitempty"`
	Typ string `json:"typ,omitempty"`
}

type JWTPayload struct {
	Sub  string `json:"sub,omitempty"`
	Name string `json:"name,omitempty"`
	Iat  int    `json:"iat,omitempty"`
	Exp  int    `json:"exp,omitempty"`
}

const (
	AlgHS256 = "HS256"
	TypJWT   = "JWT"
)

func NewJWTPayload(sub, name string, expirationSeconds int) JWTPayload {
	return JWTPayload{
		Sub:  sub,
		Name: name,
		Iat:  int(time.Now().Unix()),
		Exp:  int(time.Now().Unix()) + expirationSeconds,
	}
}

func ToBase64URL(data interface{}) (string, error) {
	jsonResp, err := json.Marshal(data)
	if err != nil {
		return "", err
	}

	encoded := base64.RawURLEncoding.EncodeToString(jsonResp)

	return encoded, nil
}

func SignToken(message, secret string) (string, error) {
	// Create HMAC using SHA256 and the secret key
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(message))
	signature := h.Sum(nil)

	// Encode the signature in Base64URL
	encodedSignature := base64.RawURLEncoding.EncodeToString(signature)
	return encodedSignature, nil
}
