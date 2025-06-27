package hashutil

import (
	"crypto/sha3"
)

func SHA3_256(data []byte) []byte {
	sum := sha3.Sum256(data)
	return sum[:]
}

func SHA3_256String(data string) []byte {
	return SHA3_256([]byte(data))
}

func SHA3_512(data []byte) []byte {
	sum := sha3.Sum512(data)
	return sum[:]
}

func SHA3_512String(data string) []byte {
	return SHA3_512([]byte(data))
}
