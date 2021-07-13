package smt

import (
	"crypto/sha256"
	"strconv"
	"testing"
)

func BenchmarkSparseMerkleTree_Update(b *testing.B) {
	smn, smv := NewSimpleMap(), NewSimpleMap()
	smt := NewSparseMerkleTree(smn, smv, sha256.New())

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		s := strconv.Itoa(i)
		_, _ = smt.Update([]byte(s), []byte(s))
	}
}

func BenchmarkSparseMerkleTree_Delete(b *testing.B) {
	smn, smv := NewSimpleMap(), NewSimpleMap()
	smt := NewSparseMerkleTree(smn, smv, sha256.New())

	for i := 0; i < 100000; i++ {
		s := strconv.Itoa(i)
		_, _ = smt.Update([]byte(s), []byte(s))
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		s := strconv.Itoa(i)
		_, _ = smt.Delete([]byte(s))
	}
}
