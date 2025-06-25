package password

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
)

// ================================================================================
// WARNING: SHA256 IS NOT SECURE FOR PASSWORDS STORAGE.
// DO NOT USE THESE IN PRODUCTION FOR STORING PASSWORDS.
// ================================================================================

type SHA256Hasher struct{}

// var _ Hasher = (*SHA256Hasher)(nil)

// func NewSHA256Hasher() *SHA256Hasher {
// 	return &SHA256Hasher{}
// }

func (h *SHA256Hasher) Hash(password string) (string, error) {
	hashBytes := h.generateHash(password)
	return hex.EncodeToString(hashBytes), nil
}

func (h *SHA256Hasher) Verify(hashedPassword, password string) bool {
	storedHashBytes, err := hex.DecodeString(hashedPassword)
	if err != nil {
		return false
	}

	comparisonHashBytes := h.generateHash(password)

	return subtle.ConstantTimeCompare(storedHashBytes, comparisonHashBytes) == 1
}

func (h *SHA256Hasher) generateHash(password string) []byte {
	sum := sha256.Sum256([]byte(password))
	return sum[:]
}
