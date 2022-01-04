package smt

import (
	"math/rand"
	"time"
)

func randomBytes(length int) []byte {
	rand.Seed(time.Now().UnixNano())
	b := make([]byte, length)
	rand.Read(b)
	return b
}
