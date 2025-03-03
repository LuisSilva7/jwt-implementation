package jwt

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"sync"
	"time"
)

const refreshTokenFile = "data/refresh_tokens.json"

// Mutex for thread safety
var refreshMu sync.Mutex

type RefreshToken struct {
	Token     string `json:"token"`
	UserID    string `json:"user_id"`
	ExpiresAt int64  `json:"expires_at"`
}

func GenerateRefreshToken(userID string, duration int64) (string, error) {
	refreshMu.Lock()
	defer refreshMu.Unlock()

	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", err
	}
	refreshToken := hex.EncodeToString(tokenBytes)

	expiresAt := time.Now().Add(time.Duration(duration) * time.Second).Unix()

	tokens, err := readRefreshTokens()
	if err != nil {
		return "", err
	}

	tokens[refreshToken] = RefreshToken{
		Token:     refreshToken,
		UserID:    userID,
		ExpiresAt: expiresAt,
	}

	err = saveRefreshTokens(tokens)
	if err != nil {
		return "", err
	}

	return refreshToken, nil
}

func readRefreshTokens() (map[string]RefreshToken, error) {
	if _, err := os.Stat(refreshTokenFile); errors.Is(err, os.ErrNotExist) {
		err := saveRefreshTokens(make(map[string]RefreshToken))
		if err != nil {
			return nil, err
		}
	}

	file, err := os.Open(refreshTokenFile)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var tokens map[string]RefreshToken
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&tokens); err != nil {
		return make(map[string]RefreshToken), nil
	}

	return tokens, nil
}

func saveRefreshTokens(tokens map[string]RefreshToken) error {
	file, err := os.Create(refreshTokenFile)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	return encoder.Encode(tokens)
}

func RefreshAccessToken(refreshToken, secret string) (string, error) {
	refreshMu.Lock()
	defer refreshMu.Unlock()

	tokens, err := readRefreshTokens()
	if err != nil {
		return "", err
	}

	storedToken, exists := tokens[refreshToken]
	if !exists {
		return "", errors.New("invalid refresh token")
	}

	if storedToken.ExpiresAt < time.Now().Unix() {
		delete(tokens, refreshToken)
		saveRefreshTokens(tokens)
		return "", errors.New("refresh token expired")
	}

	header := JWTHeader{Alg: "HS256", Typ: "JWT"}
	encodedHeader, err := ToBase64URL(header)
	if err != nil {
		return "", err
	}

	payload := JWTPayload{
		Sub:  storedToken.UserID,
		Name: "User",
		Iat:  int(time.Now().Unix()),
		Exp:  int(time.Now().Unix()) + 3600,
	}
	encodedPayload, err := ToBase64URL(payload)
	if err != nil {
		return "", err
	}

	unsignedToken := encodedHeader + "." + encodedPayload

	signature, err := SignToken(unsignedToken, secret)
	if err != nil {
		return "", err
	}

	return unsignedToken + "." + signature, nil
}
