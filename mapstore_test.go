package smt

import(
    "hash"
    "bytes"
    "crypto/sha256"
    "testing"
)

func TestSimpleMap(t *testing.T) {
    testSimpleMap(t, sha256.New())
}

func testSimpleMap(t *testing.T, hasher hash.Hash) {
    sm := NewSimpleMap()
    h := hasher
    var value []byte
    var err error

    h.Write([]byte("test"))

    // Tests for Get
    _, err = sm.Get(h.Sum(nil))
    if err == nil {
        t.Error("did not return an error when getting a non-existent key")
    }

    // Tests for Put
    err = sm.Put(h.Sum(nil), []byte("hello"))
    if err != nil {
        t.Error("updating a key returned an error")
    }
    value, err = sm.Get(h.Sum(nil))
    if bytes.Compare(value, []byte("hello")) != 0 {
        t.Error("failed to update key")
    }

    // Tests for Del
    err = sm.Del(h.Sum(nil))
    if err != nil {
        t.Error("deleting a key returned an error")
    }
    _, err = sm.Get(h.Sum(nil))
    if err == nil {
        t.Error("failed to delete key")
    }
    err = sm.Del([]byte("nonexistent"))
    if err == nil {
        t.Error("deleting a key did not return an error on a non-existent key")
    }
}
