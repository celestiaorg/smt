package smt

import(
    "bytes"
    "crypto/sha256"
    "testing"
)

func TestSimpleMap(t *testing.T) {
    sm := NewSimpleMap()
    h := sha256.New()
    var val []byte
    var err error

    h.Write([]byte("test"))

    _, err = sm.Get(h.Sum(nil))
    if err == nil {
        t.Error("did not return an error when getting a non-existent key")
    }

    err = sm.Put(h.Sum(nil), []byte("hello"))
    if err != nil {
        t.Error("updating a key returned an error")
    }
    val, err = sm.Get(h.Sum(nil))
    if bytes.Compare(val, []byte("hello")) != 0 {
        t.Error("failed to update key")
    }

    err = sm.Del(h.Sum(nil))
    if err != nil {
        t.Error("deleting a key returned an error")
    }
    _, err = sm.Get(h.Sum(nil))
    if err == nil {
        t.Error("failed to delete key")
    }
}
