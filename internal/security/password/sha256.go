package password

import (
	"crypto/subtle"
	"encoding/hex"

	"github.com/palebluedot4/go-fiber-auth-api/internal/crypto/hashutil"
)

// ================================================================================
// WARNING: SHA256 IS NOT SECURE FOR PASSWORDS STORAGE.
// DO NOT USE THESE IN PRODUCTION FOR STORING PASSWORDS.
// ================================================================================

type SHA256Hasher struct{}

// var _ Hasher = (*SHA256Hasher)(nil)

func (h *SHA256Hasher) Hash(password string) (string, error) {
	hashBytes := hashutil.SHA256String(password)
	return hex.EncodeToString(hashBytes), nil
}

func (h *SHA256Hasher) Verify(hashedPassword, password string) bool {
	storedHashBytes, err := hex.DecodeString(hashedPassword)
	if err != nil {
		return false
	}

	comparisonHashBytes := hashutil.SHA256String(password)

	return subtle.ConstantTimeCompare(storedHashBytes, comparisonHashBytes) == 1
}
