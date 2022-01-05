package smt

import (
	"math/rand"
)

func randomBytes(length int) []byte {
	b := make([]byte, length)
	rand.Read(b)
	return b
}
