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

// var _ Hasher = (*MD5Hasher)(nil) // DO NOT UNCOMMENT

// func NewMD5Hasher() *MD5Hasher {
// 	return &MD5Hasher{}
// }

func (h *MD5Hasher) Hash(password string) (string, error) {
	sum := md5.Sum([]byte(password))
	return hex.EncodeToString(sum[:]), nil
}

func (h *MD5Hasher) Verify(password, hash string) bool {
	computedHash, err := h.Hash(password)
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(computedHash), []byte(hash)) == 1
}
