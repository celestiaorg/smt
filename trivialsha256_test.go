package smt

import(
    "testing"
)

func TestTrivialSHA256(t *testing.T) {
    h := NewTrivialSHA256Hasher()
    testDeepSparseMerkleSubTree(t, h)
    testSimpleMap(t, h)
    testProofs(t, h)
    testSparseMerkleTree(t, h)
}
