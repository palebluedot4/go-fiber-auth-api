package password

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"hash"
	"strconv"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

type PBKDF2Hasher struct {
	Iterations int
	SaltLen    int
	KeyLen     int
	HashFunc   func() hash.Hash
}

var _ Hasher = (*PBKDF2Hasher)(nil)

func NewPBKDF2Hasher() *PBKDF2Hasher {
	return &PBKDF2Hasher{
		Iterations: 600000,
		SaltLen:    16,
		KeyLen:     32,
		HashFunc:   sha256.New,
	}
}

func (h *PBKDF2Hasher) Hash(password string) (string, error) {
	salt := make([]byte, h.SaltLen)
	// Per the crypto/rand documentation, Read never returns an error.
	rand.Read(salt)

	hash := pbkdf2.Key([]byte(password), salt, h.Iterations, h.KeyLen, h.HashFunc)

	encodedHash := base64.StdEncoding.EncodeToString(hash)
	encodedSalt := base64.StdEncoding.EncodeToString(salt)

	return fmt.Sprintf("pbkdf2-sha256$%d$%s$%s", h.Iterations, encodedSalt, encodedHash), nil
}

func (h *PBKDF2Hasher) Verify(hashedPassword, password string) bool {
	parts := strings.Split(hashedPassword, "$")
	if len(parts) != 4 || parts[0] != "pbkdf2-sha256" {
		return false
	}

	iterations, err := strconv.Atoi(parts[1])
	if err != nil {
		return false
	}

	salt, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		return false
	}

	storedHash, err := base64.StdEncoding.DecodeString(parts[3])
	if err != nil {
		return false
	}

	keyLen := len(storedHash)

	comparisonHash := pbkdf2.Key([]byte(password), salt, iterations, keyLen, h.HashFunc)

	return subtle.ConstantTimeCompare(storedHash, comparisonHash) == 1
}
