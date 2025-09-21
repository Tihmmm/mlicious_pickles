package util

import "bytes"

func ReadToNL(b []byte, start int) (string, bool, int) {
	for k := start; k < len(b); k++ {
		if b[k] == '\n' {
			return string(b[start:k]), true, k + 1
		}
	}

	return "", false, start
}

func Cstr(b []byte) string {
	i := bytes.IndexByte(b, 0)
	if i < 0 {
		i = len(b)
	}

	return string(b[:i])
}
