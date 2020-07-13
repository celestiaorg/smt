package smt

import (
	"bytes"
	"crypto/sha256"
	"testing"
)

// Test base case tree update operations with a few keys.
func TestSparseMerkleTreeUpdateBasic(t *testing.T) {
	sm := NewSimpleMap()
	smt := NewSparseMerkleTree(sm, sha256.New())
	var value []byte
	var err error

	// Test getting an empty key.
	value, err = smt.Get([]byte("testKey"))
	if err != nil {
		t.Errorf("returned error when getting empty key: %v", err)
	}
	if bytes.Compare(defaultValue, value) != 0 {
		t.Error("did not get default value when getting empty key")
	}

	// Test updating the empty key.
	_, err = smt.Update([]byte("testKey"), []byte("testValue"))
	if err != nil {
		t.Errorf("returned error when updating empty key: %v", err)
	}
	value, err = smt.Get([]byte("testKey"))
	if err != nil {
		t.Errorf("returned error when getting non-empty key: %v", err)
	}
	if bytes.Compare([]byte("testValue"), value) != 0 {
		t.Error("did not get correct value when getting non-empty key")
	}

	// Test updating the non-empty key.
	_, err = smt.Update([]byte("testKey"), []byte("testValue2"))
	if err != nil {
		t.Errorf("returned error when updating non-empty key: %v", err)
	}
	value, err = smt.Get([]byte("testKey"))
	if err != nil {
		t.Errorf("returned error when getting non-empty key: %v", err)
	}
	if bytes.Compare([]byte("testValue2"), value) != 0 {
		t.Error("did not get correct value when getting non-empty key")
	}

	// Test updating a second empty key.
	_, err = smt.Update([]byte("testKey2"), []byte("testValue"))
	if err != nil {
		t.Errorf("returned error when updating empty second key: %v", err)
	}
	value, err = smt.Get([]byte("testKey2"))
	if err != nil {
		t.Errorf("returned error when getting non-empty second key: %v", err)
	}
	if bytes.Compare([]byte("testValue"), value) != 0 {
		t.Error("did not get correct value when getting non-empty second key")
	}
	value, err = smt.Get([]byte("testKey"))
	if err != nil {
		t.Errorf("returned error when getting non-empty key: %v", err)
	}
	if bytes.Compare([]byte("testValue2"), value) != 0 {
		t.Error("did not get correct value when getting non-empty key")
	}

	// Test that updating a key still allows old values to be acessed from old roots.
	root := smt.Root()
	smt.Update([]byte("testKey"), []byte("testValue3"))
	value, err = smt.GetForRoot([]byte("testKey"), root)
	if err != nil {
		t.Errorf("returned error when getting non-empty key: %v", err)
	}
	if bytes.Compare([]byte("testValue2"), value) != 0 {
		t.Error("did not get correct value when getting non-empty key")
	}

	// Test that it is possible to successfully update a key in an older root.
	root, err = smt.UpdateForRoot([]byte("testKey3"), []byte("testValue4"), root)
	value, err = smt.GetForRoot([]byte("testKey3"), root)
	if err != nil {
		t.Errorf("returned error when getting non-empty key: %v", err)
	}
	if bytes.Compare([]byte("testValue4"), value) != 0 {
		t.Error("did not get correct value when getting non-empty key")
	}
	value, err = smt.GetForRoot([]byte("testKey"), root)
	if err != nil {
		t.Errorf("returned error when getting non-empty key: %v", err)
	}
	if bytes.Compare([]byte("testValue2"), value) != 0 {
		t.Error("did not get correct value when getting non-empty key")
	}

	// Test that a tree can be imported from a MapStore.
	smt2 := ImportSparseMerkleTree(sm, sha256.New(), smt.Root())
	value, err = smt2.Get([]byte("testKey"))
	if err != nil {
		t.Error("returned error when getting non-empty key")
	}
	if bytes.Compare([]byte("testValue3"), value) != 0 {
		t.Error("did not get correct value when getting non-empty key")
	}
}

// Test base case tree delete operations with a few keys.
func TestSparseMerkleTreeDeleteBasic(t *testing.T) {
	sm := NewSimpleMap()
	smt := NewSparseMerkleTree(sm, sha256.New())
	var value []byte
	var err error

	// Testing inserting, deleting a key, and inserting it again.
	smt.Update([]byte("testKey"), []byte("testValue"))
	if err != nil {
		t.Errorf("returned error when updating empty key: %v", err)
	}
	smt.Update([]byte("testKey"), defaultValue)
	if err != nil {
		t.Errorf("returned error when deleting key: %v", err)
	}
	value, err = smt.Get([]byte("testKey"))
	if err != nil {
		t.Errorf("returned error when getting deleted key: %v", err)
	}
	if bytes.Compare(defaultValue, value) != 0 {
		t.Error("did not get default value when getting deleted key")
	}
	smt.Update([]byte("testKey"), []byte("testValue"))
	if err != nil {
		t.Errorf("returned error when updating empty key: %v", err)
	}
	value, err = smt.Get([]byte("testKey"))
	if err != nil {
		t.Errorf("returned error when getting non-empty key: %v", err)
	}
	if bytes.Compare([]byte("testValue"), value) != 0 {
		t.Error("did not get correct value when getting non-empty key")
	}

	// Test inserting and deleting a second key.
	_, err = smt.Update([]byte("testKey2"), []byte("testValue"))
	if err != nil {
		t.Errorf("returned error when updating empty second key: %v", err)
	}
	smt.Update([]byte("testKey2"), defaultValue)
	if err != nil {
		t.Errorf("returned error when deleting key: %v", err)
	}
	value, err = smt.Get([]byte("testKey2"))
	if err != nil {
		t.Errorf("returned error when getting deleted key: %v", err)
	}
	if bytes.Compare(defaultValue, value) != 0 {
		t.Error("did not get default value when getting deleted key")
	}
	value, err = smt.Get([]byte("testKey"))
	if err != nil {
		t.Errorf("returned error when getting non-empty key: %v", err)
	}
	if bytes.Compare([]byte("testValue"), value) != 0 {
		t.Error("did not get correct value when getting non-empty key")
	}

	// Test inserting and deleting a different second key, when the the first bits of the two keys in the tree are different (when using SHA256).
	_, err = smt.Update([]byte("foo"), []byte("testValue"))
	if err != nil {
		t.Errorf("returned error when updating empty second key: %v", err)
	}
	smt.Update([]byte("foo"), defaultValue)
	if err != nil {
		t.Errorf("returned error when deleting key: %v", err)
	}
	value, err = smt.Get([]byte("foo"))
	if err != nil {
		t.Errorf("returned error when getting deleted key: %v", err)
	}
	if bytes.Compare(defaultValue, value) != 0 {
		t.Error("did not get default value when getting deleted key")
	}
	value, err = smt.Get([]byte("testKey"))
	if err != nil {
		t.Errorf("returned error when getting non-empty key: %v", err)
	}
	if bytes.Compare([]byte("testValue"), value) != 0 {
		t.Error("did not get correct value when getting non-empty key")
	}
}
