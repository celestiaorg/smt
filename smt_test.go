package smt

import (
	"bytes"
	"crypto/sha256"
	"hash"
	"math/rand"
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
	if !bytes.Equal(defaultValue, value) {
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
	if !bytes.Equal([]byte("testValue"), value) {
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
	if !bytes.Equal([]byte("testValue2"), value) {
		t.Error("did not get correct value when getting non-empty key")
	}

	// Test updating a second empty key where the path for both keys start with
	// different bits (when using SHA256).
	_, err = smt.Update([]byte("foo"), []byte("testValue"))
	if err != nil {
		t.Errorf("returned error when updating empty second key: %v", err)
	}
	value, err = smt.Get([]byte("foo"))
	if err != nil {
		t.Errorf("returned error when getting non-empty second key: %v", err)
	}
	if !bytes.Equal([]byte("testValue"), value) {
		t.Error("did not get correct value when getting non-empty second key")
	}

	// Test updating a third empty key.
	_, err = smt.Update([]byte("testKey2"), []byte("testValue"))
	if err != nil {
		t.Errorf("returned error when updating empty third key: %v", err)
	}
	value, err = smt.Get([]byte("testKey2"))
	if err != nil {
		t.Errorf("returned error when getting non-empty third key: %v", err)
	}
	if !bytes.Equal([]byte("testValue"), value) {
		t.Error("did not get correct value when getting non-empty third key")
	}
	value, err = smt.Get([]byte("testKey"))
	if err != nil {
		t.Errorf("returned error when getting non-empty key: %v", err)
	}
	if !bytes.Equal([]byte("testValue2"), value) {
		t.Error("did not get correct value when getting non-empty key")
	}

	// Test that updating a key still allows old values to be acessed from old roots.
	root := smt.Root()
	smt.Update([]byte("testKey"), []byte("testValue3"))
	value, err = smt.GetForRoot([]byte("testKey"), root)
	if err != nil {
		t.Errorf("returned error when getting non-empty key: %v", err)
	}
	if !bytes.Equal([]byte("testValue2"), value) {
		t.Error("did not get correct value when getting non-empty key")
	}

	// Test that it is possible to successfully update a key in an older root.
	root, err = smt.UpdateForRoot([]byte("testKey3"), []byte("testValue4"), root)
	if err != nil {
		t.Errorf("unable to update key: %v", err)
	}
	value, err = smt.GetForRoot([]byte("testKey3"), root)
	if err != nil {
		t.Errorf("returned error when getting non-empty key: %v", err)
	}
	if !bytes.Equal([]byte("testValue4"), value) {
		t.Error("did not get correct value when getting non-empty key")
	}
	value, err = smt.GetForRoot([]byte("testKey"), root)
	if err != nil {
		t.Errorf("returned error when getting non-empty key: %v", err)
	}
	if !bytes.Equal([]byte("testValue2"), value) {
		t.Error("did not get correct value when getting non-empty key")
	}

	// Test that a tree can be imported from a MapStore.
	smt2 := ImportSparseMerkleTree(sm, sha256.New(), smt.Root())
	value, err = smt2.Get([]byte("testKey"))
	if err != nil {
		t.Error("returned error when getting non-empty key")
	}
	if !bytes.Equal([]byte("testValue3"), value) {
		t.Error("did not get correct value when getting non-empty key")
	}
}

// Test tree operations when two leafs are immediate neighbours.
func TestSparseMerkleTreeMaxHeightCase(t *testing.T) {
	h := newDummyHasher(sha256.New())
	sm := NewSimpleMap()
	smt := NewSparseMerkleTree(sm, h)
	var value []byte
	var err error

	// Make two neighbouring keys.
	//
	// The dummy hash function excepts keys to prefixed with four bytes of 0,
	// which will cause it to return the preimage itself as the digest, without
	// the first four bytes.
	key1 := make([]byte, h.Size()+4)
	rand.Read(key1)
	key1[0], key1[1], key1[2], key1[3] = byte(0), byte(0), byte(0), byte(0)
	key1[h.Size()+4-1] = byte(0)
	key2 := make([]byte, h.Size()+4)
	copy(key2, key1)
	setBit(key2, (h.Size()+4)*8-1)

	_, err = smt.Update(key1, []byte("testValue1"))
	if err != nil {
		t.Errorf("returned error when updating empty key: %v", err)
	}
	_, err = smt.Update(key2, []byte("testValue2"))
	if err != nil {
		t.Errorf("returned error when updating empty key: %v", err)
	}

	value, err = smt.Get(key1)
	if err != nil {
		t.Errorf("returned error when getting non-empty key: %v", err)
	}
	if !bytes.Equal([]byte("testValue1"), value) {
		t.Error("did not get correct value when getting non-empty key")
	}

	value, err = smt.Get(key2)
	if err != nil {
		t.Errorf("returned error when getting non-empty key: %v", err)
	}
	if !bytes.Equal([]byte("testValue2"), value) {
		t.Error("did not get correct value when getting non-empty key")
	}
}

// Test base case tree delete operations with a few keys.
func TestSparseMerkleTreeDeleteBasic(t *testing.T) {
	sm := NewSimpleMap()
	smt := NewSparseMerkleTree(sm, sha256.New())

	// Testing inserting, deleting a key, and inserting it again.
	_, err := smt.Update([]byte("testKey"), []byte("testValue"))
	if err != nil {
		t.Errorf("returned error when updating empty key: %v", err)
	}
	root1 := smt.Root()
	_, err = smt.Update([]byte("testKey"), defaultValue)
	if err != nil {
		t.Errorf("returned error when deleting key: %v", err)
	}
	value, err := smt.Get([]byte("testKey"))
	if err != nil {
		t.Errorf("returned error when getting deleted key: %v", err)
	}
	if !bytes.Equal(defaultValue, value) {
		t.Error("did not get default value when getting deleted key")
	}
	_, err = smt.Update([]byte("testKey"), []byte("testValue"))
	if err != nil {
		t.Errorf("returned error when updating empty key: %v", err)
	}
	value, err = smt.Get([]byte("testKey"))
	if err != nil {
		t.Errorf("returned error when getting non-empty key: %v", err)
	}
	if !bytes.Equal([]byte("testValue"), value) {
		t.Error("did not get correct value when getting non-empty key")
	}
	if !bytes.Equal(root1, smt.Root()) {
		t.Error("tree root is not as expected after re-inserting key after deletion")
	}

	// Test inserting and deleting a second key.
	_, err = smt.Update([]byte("testKey2"), []byte("testValue"))
	if err != nil {
		t.Errorf("returned error when updating empty second key: %v", err)
	}
	_, err = smt.Update([]byte("testKey2"), defaultValue)
	if err != nil {
		t.Errorf("returned error when deleting key: %v", err)
	}
	value, err = smt.Get([]byte("testKey2"))
	if err != nil {
		t.Errorf("returned error when getting deleted key: %v", err)
	}
	if !bytes.Equal(defaultValue, value) {
		t.Error("did not get default value when getting deleted key")
	}
	value, err = smt.Get([]byte("testKey"))
	if err != nil {
		t.Errorf("returned error when getting non-empty key: %v", err)
	}
	if !bytes.Equal([]byte("testValue"), value) {
		t.Error("did not get correct value when getting non-empty key")
	}
	if !bytes.Equal(root1, smt.Root()) {
		t.Error("tree root is not as expected after deleting second key")
	}

	// Test inserting and deleting a different second key, when the the first
	// bits of the path for the two keys in the tree are different (when using SHA256).
	_, err = smt.Update([]byte("foo"), []byte("testValue"))
	if err != nil {
		t.Errorf("unable to update key: %v", err)
	}

	value, err = smt.Get([]byte("foo"))
	if err != nil {
		t.Errorf("returned error when updating empty second key: %v", err)
	}
	_, err = smt.Update([]byte("foo"), defaultValue)
	if err != nil {
		t.Errorf("returned error when deleting key: %v", err)
	}
	value, err = smt.Get([]byte("foo"))
	if err != nil {
		t.Errorf("returned error when getting deleted key: %v", err)
	}
	if !bytes.Equal(defaultValue, value) {
		t.Error("did not get default value when getting deleted key")
	}
	value, err = smt.Get([]byte("testKey"))
	if err != nil {
		t.Errorf("returned error when getting non-empty key: %v", err)
	}
	if !bytes.Equal([]byte("testValue"), value) {
		t.Error("did not get correct value when getting non-empty key")
	}
	if !bytes.Equal(root1, smt.Root()) {
		t.Error("tree root is not as expected after deleting second key")
	}
}

// dummyHasher is a dummy hasher for tests, where the digest of keys is equivalent to the preimage.
type dummyHasher struct {
	baseHasher hash.Hash
	data       []byte
}

func newDummyHasher(baseHasher hash.Hash) hash.Hash {
	return &dummyHasher{
		baseHasher: baseHasher,
	}
}

func (h *dummyHasher) Write(data []byte) (int, error) {
	h.data = append(h.data, data...)
	return len(data), nil
}

func (h *dummyHasher) Sum(prefix []byte) []byte {
	preimage := make([]byte, len(h.data))
	copy(preimage, h.data)
	preimage = append(prefix, preimage...)

	var digest []byte
	// Keys should be prefixed with four bytes of value 0.
	if bytes.Equal(preimage[:4], []byte{0, 0, 0, 0}) && len(preimage) == h.Size()+4 {
		digest = preimage[4:]
	} else {
		h.baseHasher.Write(preimage)
		digest = h.baseHasher.Sum(nil)
		h.baseHasher.Reset()
	}

	return digest
}

func (h *dummyHasher) Reset() {
	h.data = nil
}

func (h *dummyHasher) Size() int {
	return h.baseHasher.Size()
}

func (h *dummyHasher) BlockSize() int {
	return h.Size()
}
