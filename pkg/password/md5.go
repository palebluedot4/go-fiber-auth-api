package password

import (
	"crypto/md5"
	"crypto/subtle"
	"encoding/hex"
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
	hashBytes := h.generateHash(password)
	return hex.EncodeToString(hashBytes), nil
}

func (h *MD5Hasher) Verify(hashedPassword, password string) bool {
	storedHashBytes, err := hex.DecodeString(hashedPassword)
	if err != nil {
		return false
	}

	comparisonHashBytes := h.generateHash(password)

	return subtle.ConstantTimeCompare(storedHashBytes, comparisonHashBytes) == 1
}

func (h *MD5Hasher) generateHash(password string) []byte {
	sum := md5.Sum([]byte(password))
	return sum[:]
}
