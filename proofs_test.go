package smt

import(
    "crypto/sha256"
    "testing"
)

func TestProofs(t *testing.T) {
    sm := NewSimpleMap()
    smt := NewSparseMerkleTree(sm, sha256.New())
    var err error

    smt.Update([]byte("testKey"), []byte("testValue"))
    proof, err := smt.Prove([]byte("testKey"))
    if err != nil {
        t.Error("error returned when trying to prove inclusion")
    }
    result := VerifyProof(proof, smt.root, []byte("testKey"), []byte("testValue"), sha256.New())
    if !result {
        t.Error("valid proof failed to verify")
    }
    proof[0][0] = byte(0)
    result = VerifyProof(proof, smt.root, []byte("testKey"), []byte("testValue"), sha256.New())
    if result {
        t.Error("invalid proof verification returned true")
    }
}
