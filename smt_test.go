package smt

import (
	"bytes"
	"crypto/sha256"
	"math/rand"
	"testing"
)

// Test base case tree update operations with a few keys.
func TestSparseMerkleTreeUpdateBasic(t *testing.T) {
	smn, smv := NewSimpleMap(), NewSimpleMap()
	smt := NewSMTWithStorage(smn, smv, sha256.New())
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

	// Test that a tree can be imported from a MapStore.
	smt2 := ImportSMTWithStorage(smn, smv, sha256.New(), smt.Root())
	value, err = smt2.Get([]byte("testKey"))
	if err != nil {
		t.Error("returned error when getting non-empty key")
	}
	if !bytes.Equal([]byte("testValue2"), value) {
		t.Error("did not get correct value when getting non-empty key")
	}
}

// Test known tree ops
func TestSparseMerkleTreeKnown(t *testing.T) {
	ph := dummyPathHasher{32}
	smn, smv := NewSimpleMap(), NewSimpleMap()
	smt := NewSMTWithStorage(smn, smv, sha256.New(), SetPathHasher(ph))
	var value []byte
	var err error

	baseKey := make([]byte, ph.Size())
	key1 := make([]byte, ph.Size())
	key2 := make([]byte, ph.Size())
	key3 := make([]byte, ph.Size())
	key4 := make([]byte, ph.Size())
	key5 := make([]byte, ph.Size())
	copy(key1, baseKey)
	copy(key2, baseKey)
	copy(key3, baseKey)
	copy(key4, baseKey)
	copy(key5, baseKey)
	key1[0] = byte(0b00000000)
	key2[0] = byte(0b01000000)
	key3[0] = byte(0b10000000)
	key4[0] = byte(0b11000000)
	key5[0] = byte(0b11010000)

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
}

// Test tree operations when two leafs are immediate neighbors.
func TestSparseMerkleTreeMaxHeightCase(t *testing.T) {
	ph := dummyPathHasher{32}
	smn, smv := NewSimpleMap(), NewSimpleMap()
	smt := NewSMTWithStorage(smn, smv, sha256.New(), SetPathHasher(ph))
	var value []byte
	var err error

	// Make two neighboring keys.
	// The dummy hash function will return the preimage itself as the digest.
	key1 := make([]byte, ph.Size())
	key2 := make([]byte, ph.Size())
	rand.Read(key1)
	copy(key2, key1)
	// We make key2's least significant bit different than key1's
	key1[ph.Size()-1] = byte(0)
	key2[ph.Size()-1] = byte(1)

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
	smt := NewSMTWithStorage(smn, smv, sha256.New())
	rootEmpty := smt.Root()

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
	if !bytes.Equal(rootEmpty, smt.Root()) {
		t.Error("tree root is not as expected after deletion")
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

func TestOrphanRemoval(t *testing.T) {
	var smn, smv *SimpleMap
	var smt *SMTWithStorage
	var err error
	nodeCount := func() int {
		return len(smn.m)
	}

	setup := func() {
		smn, smv = NewSimpleMap(), NewSimpleMap()
		smt = NewSMTWithStorage(smn, smv, sha256.New())
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
		keys  []string
		count int
	}
	// sha256(testKey)  = 0001...
	// sha256(testKey2) = 1000... common prefix = 0; 1 root + 2 leaf = 3 nodes
	// sha256(foo)      = 0010... common prefix = 2; 1 root + 2 inner + 2 leaf = 5 nodes
	cases := []testCase{
		{[]string{"testKey2"}, 3},
		{[]string{"foo"}, 5},
		{[]string{"testKey2", "foo"}, 6},
		{[]string{"a", "b", "c", "d", "e"}, 16},
	}

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
			for _, key := range tc.keys {
				_, err = smt.Update([]byte(key), []byte("testValue2"))
				if err != nil {
					t.Errorf("returned error when updating non-empty key: %v", err)
				}
			}
			if tc.count != nodeCount() {
				t.Errorf("expected %d nodes after insertion, got: %d", tc.count, nodeCount())
			}
			for _, key := range tc.keys {
				_, err = smt.Update([]byte(key), []byte("testValue3"))
				if err != nil {
					t.Errorf("returned error when updating non-empty key: %v", err)
				}
			}
			if tc.count != nodeCount() {
				t.Errorf("expected %d nodes after insertion, got: %d", tc.count, nodeCount())
			}
			for _, key := range tc.keys {
				_, err = smt.Delete([]byte(key))
				if err != nil {
					t.Errorf("returned error when updating non-empty key: %v", err)
				}
			}
			if 1 != nodeCount() {
				t.Errorf("expected 1 nodes after deletion, got: %d", nodeCount())
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
