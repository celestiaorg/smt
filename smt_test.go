package smt

import (
    "crypto/sha256"
    "testing"
    "bytes"
)

func TestSparseMerkleTree(t *testing.T) {
    // config

    sm := NewSimpleMap()
    value := []byte("The value needs to be 32 bytes!!!")
    h := sha256.New()
    h.Write([]byte("test-key"))
    key := h.Sum(nil)
    t.Logf("value: %s (%x)\n", value, value)
    t.Logf("key: %x\n", key)

    // create tree
    smt := NewSparseMerkleTree(sm, []byte{0}, 256, h)

    // test Get
    val, err := smt.Get(key)
    if err != nil {
        t.Error(err)
    } else if bytes.Compare(val, smt.defaultValue) != 0 {
        t.Errorf("retrieved value \"%x\" does not match default value \"%x\"", val,  smt.defaultValue)
    }

    // test Update
    err = smt.Update(key, value)
    if err != nil {
        t.Error(err)
    }


    val, err = sm.Get(key)
    if err != nil {
        t.Error(err)
    } else if bytes.Compare(val, value) != 0 {
        t.Errorf("retrieved value \"%x\" does not match \"%x\"", val, value)
    }

    val, err = smt.Get(key)
    if err != nil {
        t.Error(err)
    } else if bytes.Compare(val, value) != 0 {
        t.Errorf("retrieved value \"%x\" does not match \"%x\"", val, value)
    }

}
