package smt

import(
    "crypto/sha256"
    "testing"
)

func TestSparseMerkleTree(t *testing.T) {
    sm := NewSimpleMap()
    smt := NewSparseMerkleTree(sm, []byte{0}, 256, sha256.New())
    t.Log(smt)
}
