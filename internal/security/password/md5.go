package password

import (
	"crypto/subtle"
	"encoding/hex"

	"github.com/palebluedot4/go-fiber-auth-api/internal/crypto/hashutil"
)

// ================================================================================
// WARNING: MD5 IS NOT SECURE FOR PASSWORDS STORAGE.
// DO NOT USE THESE IN PRODUCTION FOR STORING PASSWORDS.
// ================================================================================

type MD5Hasher struct{}

// var _ Hasher = (*MD5Hasher)(nil)

// func NewMD5Hasher() *MD5Hasher {
// 	return &MD5Hasher{}
// }

func (h *MD5Hasher) Hash(password string) (string, error) {
	hashBytes := hashutil.MD5String(password)
	return hex.EncodeToString(hashBytes), nil
}

func (h *MD5Hasher) Verify(hashedPassword, password string) bool {
	storedHashBytes, err := hex.DecodeString(hashedPassword)
	if err != nil {
		return false
	}

	comparisonHashBytes := hashutil.MD5String(password)

	return subtle.ConstantTimeCompare(storedHashBytes, comparisonHashBytes) == 1
}
