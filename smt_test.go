package smt

import(
    "bytes"
    "crypto/sha256"
    "testing"
)

func TestSparseMerkleTree(t *testing.T) {
    sm := NewSimpleMap()
    smt := NewSparseMerkleTree(sm, sha256.New())
    var value []byte
    var err error

    value, err = smt.Get([]byte("testKey"))
    if err != nil {
        t.Error("returned error when getting empty key")
    }
    if bytes.Compare(defaultValue, value) != 0 {
        t.Error("did not get default value when getting empty key")
    }

    err = smt.Update([]byte("testKey"), []byte("testValue"))
    if err != nil {
        t.Error("returned error when updating empty key")
    }
    value, err = smt.Get([]byte("testKey"))
    if err != nil {
        t.Error("returned error when getting non-empty key")
    }
    if bytes.Compare([]byte("testValue"), value) != 0 {
        t.Error("did not get correct value when getting non-empty key")
    }

    err = smt.Update([]byte("testKey"), []byte("testValue2"))
    if err != nil {
        t.Error("returned error when updating non-empty key")
    }
    value, err = smt.Get([]byte("testKey"))
    if err != nil {
        t.Error("returned error when getting non-empty key")
    }
    if bytes.Compare([]byte("testValue2"), value) != 0 {
        t.Error("did not get correct value when getting non-empty key")
    }

    err = smt.Update([]byte("testKey2"), []byte("testValue"))
    if err != nil {
        t.Error("returned error when updating empty second key")
    }
    value, err = smt.Get([]byte("testKey2"))
    if err != nil {
        t.Error("returned error when getting non-empty second key")
    }
    if bytes.Compare([]byte("testValue"), value) != 0 {
        t.Error("did not get correct value when getting non-empty second key")
    }

    value, err = smt.Get([]byte("testKey"))
    if err != nil {
        t.Error("returned error when getting non-empty key")
    }
    if bytes.Compare([]byte("testValue2"), value) != 0 {
        t.Error("did not get correct value when getting non-empty key")
    }
}
