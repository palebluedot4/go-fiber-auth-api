package hashutil

import (
	"crypto/md5"
)

func MD5(data []byte) []byte {
	sum := md5.Sum(data)
	return sum[:]
}

func MD5String(data string) []byte {
	return MD5([]byte(data))
}
