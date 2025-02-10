package jwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
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

func ValidateJWT(token string, secret string) (bool, error) {
	revoked, err := IsTokenRevoked(token)
	if err != nil {
		return false, errors.New("error checking token blacklist")
	}
	if revoked {
		return false, errors.New("token has been revoked")
	}

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return false, errors.New("invalid token format")
	}

	_, err = base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return false, errors.New("couldn't decode header")
	}

	decodedPayload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return false, errors.New("couldn't decode payload")
	}

	unsignedToken := parts[0] + "." + parts[1]

	expectedSignature, err := SignToken(unsignedToken, secret)
	if err != nil {
		return false, errors.New("error signing token")
	}

	if expectedSignature != parts[2] {
		return false, errors.New("invalid signature")
	}

	var payload JWTPayload
	if err := json.Unmarshal(decodedPayload, &payload); err != nil {
		return false, errors.New("couldn't parse payload")
	}

	if payload.Exp < int(time.Now().Unix()) {
		return false, errors.New("token has expired")
	}

	return true, nil
}
