package hashutil

import (
	"crypto/sha256"
	"crypto/sha512"
)

func SHA256(data []byte) []byte {
	sum := sha256.Sum256(data)
	return sum[:]
}

func SHA256String(data string) []byte {
	return SHA256([]byte(data))
}

func SHA512(data []byte) []byte {
	sum := sha512.Sum512(data)
	return sum[:]
}

func SHA512String(data string) []byte {
	return SHA512([]byte(data))
}
