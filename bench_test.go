package smt

import (
	"crypto/sha256"
	"fmt"
	"strconv"
	"testing"
)

func BenchmarkSparseMerkleTree_Update(b *testing.B) {
	hasher := sha256.New()
	smn, smv := NewSimpleMap(hasher.Size()), NewSimpleMap(9)
	smt := NewSparseMerkleTree(smn, smv, hasher)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		s := fmt.Sprintf("%09d", i)
		_, err := smt.Update([]byte(s), []byte(s))
		if err != nil {
			b.Error(err)
		}
	}
}

func BenchmarkSparseMerkleTree_Delete(b *testing.B) {
	hasher := sha256.New()
	smn, smv := NewSimpleMap(hasher.Size()), NewSimpleMap(9)
	smt := NewSparseMerkleTree(smn, smv, hasher)

	for i := 0; i < 100000; i++ {
		s := fmt.Sprintf("%09d", i)
		_, err := smt.Update([]byte(s), []byte(s))
		if err != nil {
			b.Error(err)
		}
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		s := strconv.Itoa(i)
		_, _ = smt.Delete([]byte(s))
	}
}
