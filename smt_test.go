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
	smn, smv := NewSimpleMap(), NewSimpleMap()
	smt := NewSparseMerkleTree(smn, smv, sha256.New())
	var value []byte
	var has bool
	var err error

	// Test getting an empty key.
	value, err = smt.Get([]byte("testKey"))
	if err != nil {
		t.Errorf("returned error when getting empty key: %v", err)
	}
	if !bytes.Equal(defaultValue, value) {
		t.Error("did not get default value when getting empty key")
	}
	has, err = smt.Has([]byte("testKey"))
	if err != nil {
		t.Errorf("returned error when checking presence of empty key: %v", err)
	}
	if has {
		t.Error("did not get 'false' when checking presence of empty key")
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
	has, err = smt.Has([]byte("testKey"))
	if err != nil {
		t.Errorf("returned error when checking presence of non-empty key: %v", err)
	}
	if !has {
		t.Error("did not get 'true' when checking presence of non-empty key")
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

	// Test updating a second empty key where the path for both keys share the
	// first 2 bits (when using SHA256).
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

	// Test that updating a key still allows old values to be accessed from old roots.
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
	has, err = smt.HasForRoot([]byte("testKey"), root)
	if err != nil {
		t.Errorf("returned error when checking presence of non-empty key: %v", err)
	}
	if !has {
		t.Error("did not get 'false' when checking presence of non-empty key")
	}

	// Test that it is possible to delete key in an older root.
	root, err = smt.DeleteForRoot([]byte("testKey3"), root)
	if err != nil {
		t.Errorf("unable to delete key: %v", err)
	}
	value, err = smt.GetForRoot([]byte("testKey3"), root)
	if err != nil {
		t.Errorf("returned error when getting empty key: %v", err)
	}
	if !bytes.Equal(defaultValue, value) {
		t.Error("did not get correct value when getting empty key")
	}
	has, err = smt.HasForRoot([]byte("testKey3"), root)
	if err != nil {
		t.Errorf("returned error when checking presence of empty key: %v", err)
	}
	if has {
		t.Error("did not get 'false' when checking presence of empty key")
	}

	// Test that a tree can be imported from a MapStore.
	smt2 := ImportSparseMerkleTree(smn, smv, sha256.New(), smt.Root())
	value, err = smt2.Get([]byte("testKey"))
	if err != nil {
		t.Error("returned error when getting non-empty key")
	}
	if !bytes.Equal([]byte("testValue3"), value) {
		t.Error("did not get correct value when getting non-empty key")
	}
}

// Test known tree ops
func TestSparseMerkleTreeKnown(t *testing.T) {
	h := newDummyHasher(sha256.New())
	smn, smv := NewSimpleMap(), NewSimpleMap()
	smt := NewSparseMerkleTree(smn, smv, h)
	var value []byte
	var err error

	baseKey := make([]byte, h.Size()+4)
	key1 := make([]byte, h.Size()+4)
	copy(key1, baseKey)
	key1[4] = byte(0b00000000)
	key2 := make([]byte, h.Size()+4)
	copy(key2, baseKey)
	key2[4] = byte(0b01000000)
	key3 := make([]byte, h.Size()+4)
	copy(key3, baseKey)
	key3[4] = byte(0b10000000)
	key4 := make([]byte, h.Size()+4)
	copy(key4, baseKey)
	key4[4] = byte(0b11000000)
	key5 := make([]byte, h.Size()+4)
	copy(key5, baseKey)
	key5[4] = byte(0b11010000)

	_, err = smt.Update(key1, []byte("testValue1"))
	if err != nil {
		t.Errorf("returned error when updating empty key: %v", err)
	}
	_, err = smt.Update(key2, []byte("testValue2"))
	if err != nil {
		t.Errorf("returned error when updating empty key: %v", err)
	}
	_, err = smt.Update(key3, []byte("testValue3"))
	if err != nil {
		t.Errorf("returned error when updating empty key: %v", err)
	}
	_, err = smt.Update(key4, []byte("testValue4"))
	if err != nil {
		t.Errorf("returned error when updating empty key: %v", err)
	}
	_, err = smt.Update(key5, []byte("testValue5"))
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
	value, err = smt.Get(key3)
	if err != nil {
		t.Errorf("returned error when getting non-empty key: %v", err)
	}
	if !bytes.Equal([]byte("testValue3"), value) {
		t.Error("did not get correct value when getting non-empty key")
	}
	value, err = smt.Get(key4)
	if err != nil {
		t.Errorf("returned error when getting non-empty key: %v", err)
	}
	if !bytes.Equal([]byte("testValue4"), value) {
		t.Error("did not get correct value when getting non-empty key")
	}
	value, err = smt.Get(key5)
	if err != nil {
		t.Errorf("returned error when getting non-empty key: %v", err)
	}
	if !bytes.Equal([]byte("testValue5"), value) {
		t.Error("did not get correct value when getting non-empty key")
	}

	proof1, _ := smt.Prove(key1)
	proof2, _ := smt.Prove(key2)
	proof3, _ := smt.Prove(key3)
	proof4, _ := smt.Prove(key4)
	proof5, _ := smt.Prove(key5)
	dsmst := NewDeepSparseMerkleSubTree(NewSimpleMap(), NewSimpleMap(), h, smt.Root())
	err = dsmst.AddBranch(proof1, key1, []byte("testValue1"))
	if err != nil {
		t.Errorf("returned error when adding branch to deep subtree: %v", err)
	}
	err = dsmst.AddBranch(proof2, key2, []byte("testValue2"))
	if err != nil {
		t.Errorf("returned error when adding branch to deep subtree: %v", err)
	}
	err = dsmst.AddBranch(proof3, key3, []byte("testValue3"))
	if err != nil {
		t.Errorf("returned error when adding branch to deep subtree: %v", err)
	}
	err = dsmst.AddBranch(proof4, key4, []byte("testValue4"))
	if err != nil {
		t.Errorf("returned error when adding branch to deep subtree: %v", err)
	}
	err = dsmst.AddBranch(proof5, key5, []byte("testValue5"))
	if err != nil {
		t.Errorf("returned error when adding branch to deep subtree: %v", err)
	}
}

// Test tree operations when two leafs are immediate neighbors.
func TestSparseMerkleTreeMaxHeightCase(t *testing.T) {
	h := newDummyHasher(sha256.New())
	smn, smv := NewSimpleMap(), NewSimpleMap()
	smt := NewSparseMerkleTree(smn, smv, h)
	var value []byte
	var err error

	// Make two neighboring keys.
	//
	// The dummy hash function expects keys to prefixed with four bytes of 0,
	// which will cause it to return the preimage itself as the digest, without
	// the first four bytes.
	key1 := make([]byte, h.Size()+4)
	rand.Read(key1)
	key1[0], key1[1], key1[2], key1[3] = byte(0), byte(0), byte(0), byte(0)
	key1[h.Size()+4-1] = byte(0)
	key2 := make([]byte, h.Size()+4)
	copy(key2, key1)
	// We make key2's least significant bit different than key1's
	key2[h.Size()+4-1] = byte(1)

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

	proof, err := smt.Prove(key1)
	if err != nil {
		t.Errorf("returned error when proving key: %v", err)
	}
	if len(proof.SideNodes) != 256 {
		t.Errorf("unexpected proof size")
	}
}

// Test base case tree delete operations with a few keys.
func TestSparseMerkleTreeDeleteBasic(t *testing.T) {
	smn, smv := NewSimpleMap(), NewSimpleMap()
	smt := NewSparseMerkleTree(smn, smv, sha256.New())

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
	has, err := smt.Has([]byte("testKey"))
	if err != nil {
		t.Errorf("returned error when checking existence of deleted key: %v", err)
	}
	if has {
		t.Error("returned 'true' when checking existernce of deleted key")
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

	// Test inserting and deleting a different second key, when the the first 2
	// bits of the path for the two keys in the tree are the same (when using SHA256).
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

	// Testing inserting, deleting a key, and inserting it again, using Delete
	_, err = smt.Update([]byte("testKey"), []byte("testValue"))
	if err != nil {
		t.Errorf("returned error when updating empty key: %v", err)
	}
	root1 = smt.Root()
	_, err = smt.Delete([]byte("testKey"))
	if err != nil {
		t.Errorf("returned error when deleting key: %v", err)
	}
	value, err = smt.Get([]byte("testKey"))
	if err != nil {
		t.Errorf("returned error when getting deleted key: %v", err)
	}
	if !bytes.Equal(defaultValue, value) {
		t.Error("did not get default value when getting deleted key")
	}
	has, err = smt.Has([]byte("testKey"))
	if err != nil {
		t.Errorf("returned error when checking existence of deleted key: %v", err)
	}
	if has {
		t.Error("returned 'true' when checking existernce of deleted key")
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

func TestOrphanRemoval(t *testing.T) {
	var smn, smv *SimpleMap
	var smt *SparseMerkleTree
	var err error
	nodeCount := func() int {
		return len(smn.m)
	}

	setup := func() {
		smn, smv = NewSimpleMap(), NewSimpleMap()
		smt = NewSparseMerkleTree(smn, smv, sha256.New(), AutoRemoveOrphans())
		_, err = smt.Update([]byte("testKey"), []byte("testValue"))
		if err != nil {
			t.Errorf("returned error when updating empty key: %v", err)
		}
		// only root and value mapping
		if 1 != nodeCount() {
			t.Errorf("expected 1 nodes after insertion, got: %d", nodeCount())
		}
	}

	t.Run("delete 1", func(t *testing.T) {
		setup()
		_, err = smt.Delete([]byte("testKey"))
		if err != nil {
			t.Errorf("returned error when updating non-empty key: %v", err)
		}
		if 0 != nodeCount() {
			t.Errorf("expected 0 nodes after deletion, got: %d", nodeCount())
		}
	})

	t.Run("overwrite 1", func(t *testing.T) {
		setup()
		_, err = smt.Update([]byte("testKey"), []byte("testValue2"))
		if err != nil {
			t.Errorf("returned error when updating non-empty key: %v", err)
		}
		// Overwritten value should be pruned
		if 1 != nodeCount() {
			t.Errorf("expected 1 nodes after insertion, got: %d", nodeCount())
		}
	})

	type testCase struct {
		newKey string
		count  int
	}
	cases := []testCase{
		{"testKey2", 3}, // common prefix = 0, root + 2 leaves
		{"foo", 5},      // common prefix = 2, root + 2 node branch + 2 leaves
	}

	t.Run("delete multiple", func(t *testing.T) {
		for _, tc := range cases {
			setup()
			_, err = smt.Update([]byte(tc.newKey), []byte("testValue2"))
			if err != nil {
				t.Errorf("returned error when updating non-empty key: %v", err)
			}
			if tc.count != nodeCount() {
				t.Errorf("expected %d nodes after insertion, got: %d", tc.count, nodeCount())
			}
			_, err = smt.Delete([]byte("testKey"))
			if err != nil {
				t.Errorf("returned error when updating non-empty key: %v", err)
			}
			if 1 != nodeCount() {
				t.Errorf("expected 1 nodes after deletion, got: %d", nodeCount())
			}
			_, err = smt.Delete([]byte(tc.newKey))
			if err != nil {
				t.Errorf("returned error when updating non-empty key: %v", err)
			}
			if 0 != nodeCount() {
				t.Errorf("expected 0 nodes after deletion, got: %d", nodeCount())
			}
		}
	})

	t.Run("overwrite and delete", func(t *testing.T) {
		setup()
		_, err = smt.Update([]byte("testKey"), []byte("testValue2"))
		if err != nil {
			t.Errorf("returned error when updating non-empty key: %v", err)
		}
		if 1 != nodeCount() {
			t.Errorf("expected 1 nodes after insertion, got: %d", nodeCount())
		}
		_, err = smt.Delete([]byte("testKey"))
		if err != nil {
			t.Errorf("returned error when updating non-empty key: %v", err)
		}
		if 0 != nodeCount() {
			t.Errorf("expected 0 nodes after deletion, got: %d", nodeCount())
		}

		for _, tc := range cases {
			setup()
			_, err = smt.Update([]byte(tc.newKey), []byte("testValue2"))
			if err != nil {
				t.Errorf("returned error when updating non-empty key: %v", err)
			}
			if tc.count != nodeCount() {
				t.Errorf("expected 1 nodes after insertion, got: %d", nodeCount())
			}
			_, err = smt.Update([]byte(tc.newKey), []byte("testValue3"))
			if err != nil {
				t.Errorf("returned error when updating non-empty key: %v", err)
			}
			if tc.count != nodeCount() {
				t.Errorf("expected %d nodes after insertion, got: %d", tc.count, nodeCount())
			}
			_, err = smt.Delete([]byte("testKey"))
			if err != nil {
				t.Errorf("returned error when updating non-empty key: %v", err)
			}
			if 1 != nodeCount() {
				t.Errorf("expected 1 nodes after deletion, got: %d", nodeCount())
			}
			_, err = smt.Delete([]byte(tc.newKey))
			if err != nil {
				t.Errorf("returned error when updating non-empty key: %v", err)
			}
			if 0 != nodeCount() {
				t.Errorf("expected 0 nodes after deletion, got: %d", nodeCount())
			}

		}
	})

	t.Run("delete duplicate value", func(t *testing.T) {
		setup()
		_, err = smt.Update([]byte("testKey2"), []byte("testValue"))
		if err != nil {
			t.Errorf("returned error when updating non-empty key: %v", err)
		}
		_, err = smt.Delete([]byte("testKey"))
		if err != nil {
			t.Errorf("returned error when updating non-empty key: %v", err)
		}
		_, err = smt.Delete([]byte("testKey2"))
		if err != nil {
			t.Errorf("returned error when updating non-empty key: %v", err)
		}
	})
}
