package smt

import(
    "crypto/sha256"
    "testing"
)

func TestSparseMerkleTree(t *testing.T) {
    h := sha256.New()
    sm := NewSimpleMap()
    smt := NewSparseMerkleTree(sm, []byte{0}, 256, h)
    h.Write([]byte("test"))
    key := h.Sum(nil)
    t.Log(smt.Get(key))
    smt.Update(key, []byte("lol"))
    t.Log(smt.Get(key))
}
