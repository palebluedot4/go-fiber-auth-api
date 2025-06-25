package hashutil

import (
	"crypto/sha3"
)

func SHA3(data []byte) []byte {
	sum := sha3.Sum256(data)
	return sum[:]
}

func SHA3String(data string) []byte {
	return SHA3([]byte(data))
}
