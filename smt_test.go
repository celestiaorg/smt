package smt

import (
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
	if bytes.Compare(smt.DefaultValue(), value) != 0 {
		t.Error("did not get default value when getting empty key")
	}

	_, err = smt.Update([]byte("testKey"), []byte("testValue"))
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

	_, err = smt.Update([]byte("testKey"), []byte("testValue2"))
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

	_, err = smt.Update([]byte("testKey2"), []byte("testValue"))
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

	root := smt.Root()
	smt.Update([]byte("testKey"), []byte("testValue3"))

	value, err = smt.GetForRoot([]byte("testKey"), root)
	if err != nil {
		t.Error("returned error when getting non-empty key")
	}
	if bytes.Compare([]byte("testValue2"), value) != 0 {
		t.Error("did not get correct value when getting non-empty key")
	}

	root, err = smt.UpdateForRoot([]byte("testKey3"), []byte("testValue4"), root)

	value, err = smt.GetForRoot([]byte("testKey3"), root)
	if err != nil {
		t.Error("returned error when getting non-empty key")
	}
	if bytes.Compare([]byte("testValue4"), value) != 0 {
		t.Error("did not get correct value when getting non-empty key")
	}

	value, err = smt.GetForRoot([]byte("testKey"), root)
	if err != nil {
		t.Error("returned error when getting non-empty key")
	}
	if bytes.Compare([]byte("testValue2"), value) != 0 {
		t.Error("did not get correct value when getting non-empty key")
	}

	smt2 := ImportSparseMerkleTree(sm, sha256.New(), smt.Root())

	value, err = smt2.Get([]byte("testKey"))
	if err != nil {
		t.Error("returned error when getting non-empty key")
	}
	if bytes.Compare([]byte("testValue3"), value) != 0 {
		t.Error("did not get correct value when getting non-empty key")
	}
}
