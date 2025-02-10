package jwt

import (
	"encoding/json"
	"errors"
	"os"
	"sync"
)

const blacklistFile = "data/revoked_tokens.json"

// Mutex to handle concurrent access
var mu sync.Mutex

func RevokeToken(token string) error {
	mu.Lock()
	defer mu.Unlock()

	tokens, err := readBlacklist()
	if err != nil {
		return err
	}

	tokens[token] = true

	return saveBlacklist(tokens)
}

func IsTokenRevoked(token string) (bool, error) {
	mu.Lock()
	defer mu.Unlock()

	tokens, err := readBlacklist()
	if err != nil {
		return false, err
	}

	_, revoked := tokens[token]
	return revoked, nil
}

func readBlacklist() (map[string]bool, error) {
	if _, err := os.Stat(blacklistFile); errors.Is(err, os.ErrNotExist) {
		err := saveBlacklist(make(map[string]bool))
		if err != nil {
			return nil, err
		}
	}

	file, err := os.Open(blacklistFile)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var tokens map[string]bool
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&tokens); err != nil {
		return make(map[string]bool), saveBlacklist(make(map[string]bool))
	}

	return tokens, nil
}

func saveBlacklist(tokens map[string]bool) error {
	file, err := os.Create(blacklistFile)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	return encoder.Encode(tokens)
}
