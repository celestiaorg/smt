package smt

import (
	"bytes"
	"crypto/sha256"
	"math/rand"
	"testing"
)

func TestSparseMerkleTreeKeySizeChecks(t *testing.T) {
	hasher := sha256.New()
	keySize := len([]byte("testKey1"))
	smn, _ := NewSimpleMap(hasher.Size())
	smv, _ := NewSimpleMap(keySize)
	smt := NewSparseMerkleTree(smn, smv, hasher)

	_, _ = smt.Update([]byte("testKey1"), []byte("testValue1"))
	_, _ = smt.Update([]byte("testKey2"), []byte("testValue2"))

	_, err := smt.Get(randomBytes(keySize + 1))
	if err != ErrWrongKeySize {
		t.Errorf("should have returned wrong key size exception when getting `keySize + 1`. Actual exception: %v", err)
	}
	_, err = smt.Get(randomBytes(keySize - 1))
	if err != ErrWrongKeySize {
		t.Errorf("should have returned wrong key size exception when getting `keySize - 1`. Actual exception: %v", err)
	}

	_, err = smt.Update(randomBytes(keySize+1), []byte("testValue1"))
	if err != ErrWrongKeySize {
		t.Errorf("should have returned wrong key size exception when updating `keySize + 1`. Actual exception: %v", err)
	}

	_, err = smt.Update(randomBytes(keySize-1), []byte("testValue1"))
	if err != ErrWrongKeySize {
		t.Errorf("should have returned wrong key size exception when updating `keySize - 1`. Actual exception: %v", err)
	}

	_, err = smt.Prove(randomBytes(keySize + 1))
	if err != ErrWrongKeySize {
		t.Errorf("should have returned wrong key size exception when proving `keySize + 1`. Actual exception: %v", err)
	}

	_, err = smt.Prove(randomBytes(keySize - 1))
	if err != ErrWrongKeySize {
		t.Errorf("should have returned wrong key size exception when proving `keySize + 1`. Actual exception: %v", err)
	}

	_, err = smt.Delete(randomBytes(keySize + 1))
	if err != ErrWrongKeySize {
		t.Errorf("should have returned wrong key size exception when deleting `keySize + 1`. Actual exception: %v", err)
	}

	_, err = smt.Delete(randomBytes(keySize - 1))
	if err != ErrWrongKeySize {
		t.Errorf("should have returned wrong key size exception when deleting `keySize - 1`. Actual exception: %v", err)
	}

	_, err = smt.DeleteForRoot(randomBytes(keySize+1), smt.Root())
	if err != ErrWrongKeySize {
		t.Errorf("should have returned wrong key size exception when delete for root `keySize + 1`. Actual exception: %v", err)
	}

	_, err = smt.DeleteForRoot(randomBytes(keySize-1), smt.Root())
	if err != ErrWrongKeySize {
		t.Errorf("should have returned wrong key size exception when delete for root `keySize - 1`. Actual exception: %v", err)
	}

	_, err = smt.GetDescend(randomBytes(keySize + 1))
	if err != ErrWrongKeySize {
		t.Errorf("should have returned wrong key size exception when get descend for `keySize + 1`. Actual exception: %v", err)
	}

	_, err = smt.GetDescend(randomBytes(keySize - 1))
	if err != ErrWrongKeySize {
		t.Errorf("should have returned wrong key size exception when get descend for `keySize - 1`. Actual exception: %v", err)
	}

	_, err = smt.Has(randomBytes(keySize + 1))
	if err != ErrWrongKeySize {
		t.Errorf("should have returned wrong key size exception when has `keySize + 1`. Actual exception: %v", err)
	}

	_, err = smt.Has(randomBytes(keySize - 1))
	if err != ErrWrongKeySize {
		t.Errorf("should have returned wrong key size exception when has `keySize - 1`. Actual exception: %v", err)
	}

	_, err = smt.HasDescend(randomBytes(keySize + 1))
	if err != ErrWrongKeySize {
		t.Errorf("should have returned wrong key size exception when has descend `keySize + 1`. Actual exception: %v", err)
	}

	_, err = smt.HasDescend(randomBytes(keySize - 1))
	if err != ErrWrongKeySize {
		t.Errorf("should have returned wrong key size exception when has descend `keySize - 1`. Actual exception: %v", err)
	}

	_, err = smt.ProveCompact(randomBytes(keySize + 1))
	if err != ErrWrongKeySize {
		t.Errorf("should have returned wrong key size exception when prove compact for `keySize + 1`. Actual exception: %v", err)
	}

	_, err = smt.ProveCompact(randomBytes(keySize - 1))
	if err != ErrWrongKeySize {
		t.Errorf("should have returned wrong key size exception when prove compact for `keySize - 1`. Actual exception: %v", err)
	}

	_, err = smt.ProveCompactForRoot(randomBytes(keySize+1), smt.Root())
	if err != ErrWrongKeySize {
		t.Errorf("should have returned wrong key size exception when prove compact for root for `keySize + 1`. Actual exception: %v", err)
	}

	_, err = smt.ProveCompactForRoot(randomBytes(keySize-1), smt.Root())
	if err != ErrWrongKeySize {
		t.Errorf("should have returned wrong key size exception when prove compact for root for `keySize - 1`. Actual exception: %v", err)
	}

	_, err = smt.ProveForRoot(randomBytes(keySize+1), smt.Root())
	if err != ErrWrongKeySize {
		t.Errorf("should have returned wrong key size exception when prove for root for `keySize + 1`. Actual exception: %v", err)
	}

	_, err = smt.ProveForRoot(randomBytes(keySize-1), smt.Root())
	if err != ErrWrongKeySize {
		t.Errorf("should have returned wrong key size exception when prove for root for `keySize - 1`. Actual exception: %v", err)
	}

	_, err = smt.ProveUpdatable(randomBytes(keySize + 1))
	if err != ErrWrongKeySize {
		t.Errorf("should have returned wrong key size exception when prove updatable for `keySize + 1`. Actual exception: %v", err)
	}

	_, err = smt.ProveUpdatable(randomBytes(keySize - 1))
	if err != ErrWrongKeySize {
		t.Errorf("should have returned wrong key size exception when prove updatable for `keySize - 1`. Actual exception: %v", err)
	}

	_, err = smt.ProveUpdatableForRoot(randomBytes(keySize+1), smt.Root())
	if err != ErrWrongKeySize {
		t.Errorf("should have returned wrong key size exception when prove updatable for root for `keySize + 1`. Actual exception: %v", err)
	}

	_, err = smt.ProveUpdatableForRoot(randomBytes(keySize-1), smt.Root())
	if err != ErrWrongKeySize {
		t.Errorf("should have returned wrong key size exception when prove updatable for root for `keySize - 1`. Actual exception: %v", err)
	}

	_, err = smt.UpdateForRoot(randomBytes(keySize+1), []byte("testValue1"), smt.Root())
	if err != ErrWrongKeySize {
		t.Errorf("should have returned wrong key size exception when updating for root for `keySize + 1`. Actual exception: %v", err)
	}

	_, err = smt.UpdateForRoot(randomBytes(keySize-1), []byte("testValue1"), smt.Root())
	if err != ErrWrongKeySize {
		t.Errorf("should have returned wrong key size exception when updating for root for `keySize - 1`. Actual exception: %v", err)
	}
}

// Test base case tree update operations with a few keys.
func TestSparseMerkleTreeUpdateBasic(t *testing.T) {
	hasher := sha256.New()
	keySize := len([]byte("testKey1"))
	smn, _ := NewSimpleMap(hasher.Size())
	smv, _ := NewSimpleMap(keySize)
	smt := NewSparseMerkleTree(smn, smv, hasher)
	var value []byte
	var has bool
	var err error

	// Test getting an empty key.
	value, err = smt.Get([]byte("testKey1"))
	if err != nil {
		t.Errorf("returned error when getting empty key: %v", err)
	}
	if !bytes.Equal(defaultValue, value) {
		t.Error("did not get default value when getting empty key")
	}
	has, err = smt.Has([]byte("testKey1"))
	if err != nil {
		t.Errorf("returned error when checking presence of empty key: %v", err)
	}
	if has {
		t.Error("did not get 'false' when checking presence of empty key")
	}

	// Test updating the empty key.
	_, err = smt.Update([]byte("testKey1"), []byte("testValue1"))
	if err != nil {
		t.Errorf("returned error when updating empty key: %v", err)
	}
	value, err = smt.Get([]byte("testKey1"))
	if err != nil {
		t.Errorf("returned error when getting non-empty key: %v", err)
	}
	if !bytes.Equal([]byte("testValue1"), value) {
		t.Error("did not get correct value when getting non-empty key")
	}
	has, err = smt.Has([]byte("testKey1"))
	if err != nil {
		t.Errorf("returned error when checking presence of non-empty key: %v", err)
	}
	if !has {
		t.Error("did not get 'true' when checking presence of non-empty key")
	}

	// Test updating the non-empty key.
	_, err = smt.Update([]byte("testKey1"), []byte("testValue2"))
	if err != nil {
		t.Errorf("returned error when updating non-empty key: %v", err)
	}
	value, err = smt.Get([]byte("testKey1"))
	if err != nil {
		t.Errorf("returned error when getting non-empty key: %v", err)
	}
	if !bytes.Equal([]byte("testValue2"), value) {
		t.Error("did not get correct value when getting non-empty key")
	}

	// Test updating a second empty key where the path differs in the first 8 bits
	differentTestKey := make([]byte, keySize)
	copy(differentTestKey, "testKey1")
	differentTestKey[0] = differentTestKey[0] << 2
	_, err = smt.Update(differentTestKey, []byte("testValue1"))
	if err != nil {
		t.Errorf("returned error when updating empty second key: %v", err)
	}
	value, err = smt.Get(differentTestKey)
	if err != nil {
		t.Errorf("returned error when getting non-empty second key: %v", err)
	}
	if !bytes.Equal([]byte("testValue1"), value) {
		t.Error("did not get correct value when getting non-empty second key")
	}

	// Test updating a third empty key.
	_, err = smt.Update([]byte("testKey2"), []byte("testValue1"))
	if err != nil {
		t.Errorf("returned error when updating empty third key: %v", err)
	}
	value, err = smt.Get([]byte("testKey2"))
	if err != nil {
		t.Errorf("returned error when getting non-empty third key: %v", err)
	}
	if !bytes.Equal([]byte("testValue1"), value) {
		t.Error("did not get correct value when getting non-empty third key")
	}
	value, err = smt.Get([]byte("testKey1"))
	if err != nil {
		t.Errorf("returned error when getting non-empty key: %v", err)
	}
	if !bytes.Equal([]byte("testValue2"), value) {
		t.Error("did not get correct value when getting non-empty key")
	}

	// Test that a tree can be imported from a MapStore.
	smt2 := ImportSparseMerkleTree(smn, smv, sha256.New(), smt.Root())
	value, err = smt2.Get([]byte("testKey1"))
	if err != nil {
		t.Error("returned error when getting non-empty key")
	}
	if !bytes.Equal([]byte("testValue2"), value) {
		t.Error("did not get correct value when getting non-empty key")
	}
}

// Test known tree ops
func TestSparseMerkleTreeKnown(t *testing.T) {
	h := sha256.New()
	keySize := 16
	smn, _ := NewSimpleMap(h.Size())
	smv, _ := NewSimpleMap(keySize)
	smt := NewSparseMerkleTree(smn, smv, h)
	var value []byte
	var err error

	baseKey := make([]byte, keySize)
	key1 := make([]byte, keySize)
	copy(key1, baseKey)
	key1[4] = byte(0b00000000)
	key2 := make([]byte, keySize)
	copy(key2, baseKey)
	key2[4] = byte(0b01000000)
	key3 := make([]byte, keySize)
	copy(key3, baseKey)
	key3[4] = byte(0b10000000)
	key4 := make([]byte, keySize)
	copy(key4, baseKey)
	key4[4] = byte(0b11000000)
	key5 := make([]byte, keySize)
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

	smn, _ = NewSimpleMap(h.Size())
	smv, _ = NewSimpleMap(keySize)
	dsmst := NewDeepSparseMerkleSubTree(smn, smv, h, smt.Root())
	err = dsmst.AddBranch(proof1, key1, []byte("testValue1"), smt.values.GetKeySize())
	if err != nil {
		t.Errorf("returned error when adding branch to deep subtree: %v", err)
	}
	err = dsmst.AddBranch(proof2, key2, []byte("testValue2"), smt.values.GetKeySize())
	if err != nil {
		t.Errorf("returned error when adding branch to deep subtree: %v", err)
	}
	err = dsmst.AddBranch(proof3, key3, []byte("testValue3"), smt.values.GetKeySize())
	if err != nil {
		t.Errorf("returned error when adding branch to deep subtree: %v", err)
	}
	err = dsmst.AddBranch(proof4, key4, []byte("testValue4"), smt.values.GetKeySize())
	if err != nil {
		t.Errorf("returned error when adding branch to deep subtree: %v", err)
	}
	err = dsmst.AddBranch(proof5, key5, []byte("testValue5"), smt.values.GetKeySize())
	if err != nil {
		t.Errorf("returned error when adding branch to deep subtree: %v", err)
	}
}

// Test tree operations when two leafs are immediate neighbors.
func TestSparseMerkleTreeMaxHeightCase(t *testing.T) {
	hasher := sha256.New()
	keySize := hasher.Size()
	smn, _ := NewSimpleMap(keySize)
	smv, _ := NewSimpleMap(keySize)
	smt := NewSparseMerkleTree(smn, smv, hasher)
	var value []byte
	var err error

	// Make two neighboring keys.
	key1 := make([]byte, keySize)
	rand.Read(key1)
	key1[0], key1[1], key1[2], key1[3] = byte(0), byte(0), byte(0), byte(0)
	key1[keySize-1] = byte(0)
	key2 := make([]byte, keySize)
	copy(key2, key1)
	// We make key2's least significant bit different than key1's
	key2[keySize-1] = byte(1)

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
	hasher := sha256.New()
	smn, _ := NewSimpleMap(hasher.Size())
	smv, _ := NewSimpleMap(len([]byte("testKey1")))
	smt := NewSparseMerkleTree(smn, smv, hasher)

	// Testing inserting, deleting a key, and inserting it again.
	_, err := smt.Update([]byte("testKey1"), []byte("testValue1"))
	if err != nil {
		t.Errorf("returned error when updating empty key: %v", err)
	}
	root1 := smt.Root()
	_, err = smt.Update([]byte("testKey1"), defaultValue)
	if err != nil {
		t.Errorf("returned error when deleting key: %v", err)
	}
	value, err := smt.Get([]byte("testKey1"))
	if err != nil {
		t.Errorf("returned error when getting deleted key: %v", err)
	}
	if !bytes.Equal(defaultValue, value) {
		t.Error("did not get default value when getting deleted key")
	}
	has, err := smt.Has([]byte("testKey1"))
	if err != nil {
		t.Errorf("returned error when checking existence of deleted key: %v", err)
	}
	if has {
		t.Error("returned 'true' when checking existence of deleted key")
	}
	_, err = smt.Update([]byte("testKey1"), []byte("testValue1"))
	if err != nil {
		t.Errorf("returned error when updating empty key: %v", err)
	}
	value, err = smt.Get([]byte("testKey1"))
	if err != nil {
		t.Errorf("returned error when getting non-empty key: %v", err)
	}
	if !bytes.Equal([]byte("testValue1"), value) {
		t.Error("did not get correct value when getting non-empty key")
	}
	if !bytes.Equal(root1, smt.Root()) {
		t.Error("tree root is not as expected after re-inserting key after deletion")
	}

	// Test inserting and deleting a second key.
	_, err = smt.Update([]byte("testKey2"), []byte("testValue1"))
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
	value, err = smt.Get([]byte("testKey1"))
	if err != nil {
		t.Errorf("returned error when getting non-empty key: %v", err)
	}
	if !bytes.Equal([]byte("testValue1"), value) {
		t.Error("did not get correct value when getting non-empty key")
	}
	if !bytes.Equal(root1, smt.Root()) {
		t.Error("tree root is not as expected after deleting second key")
	}

	// Test inserting and deleting a different second key, when the first 2
	// bits of the path for the two keys in the tree are the same.
	differentTestKey := make([]byte, len([]byte("testKey1")))
	copy(differentTestKey, "testKey1")
	differentTestKey[0] = byte(0b1000000)
	countCommonPrefix([]byte("testKey1"), differentTestKey)
	_, err = smt.Update(differentTestKey, []byte("testValue1"))
	if err != nil {
		t.Errorf("unable to update key: %v", err)
	}

	value, err = smt.Get(differentTestKey)
	if err != nil {
		t.Errorf("returned error when updating empty second key: %v", err)
	}
	_, err = smt.Update(differentTestKey, defaultValue)
	if err != nil {
		t.Errorf("returned error when deleting key: %v", err)
	}
	value, err = smt.Get(differentTestKey)
	if err != nil {
		t.Errorf("returned error when getting deleted key: %v", err)
	}
	if !bytes.Equal(defaultValue, value) {
		t.Error("did not get default value when getting deleted key")
	}
	value, err = smt.Get([]byte("testKey1"))
	if err != nil {
		t.Errorf("returned error when getting non-empty key: %v", err)
	}
	if !bytes.Equal([]byte("testValue1"), value) {
		t.Error("did not get correct value when getting non-empty key")
	}
	if !bytes.Equal(root1, smt.Root()) {
		t.Error("tree root is not as expected after deleting second key")
	}

	// Testing inserting, deleting a key, and inserting it again, using Delete
	_, err = smt.Update([]byte("testKey1"), []byte("testValue1"))
	if err != nil {
		t.Errorf("returned error when updating empty key: %v", err)
	}
	root1 = smt.Root()
	_, err = smt.Delete([]byte("testKey1"))
	if err != nil {
		t.Errorf("returned error when deleting key: %v", err)
	}
	value, err = smt.Get([]byte("testKey1"))
	if err != nil {
		t.Errorf("returned error when getting deleted key: %v", err)
	}
	if !bytes.Equal(defaultValue, value) {
		t.Error("did not get default value when getting deleted key")
	}
	has, err = smt.Has([]byte("testKey1"))
	if err != nil {
		t.Errorf("returned error when checking existence of deleted key: %v", err)
	}
	if has {
		t.Error("returned 'true' when checking existence of deleted key")
	}
	_, err = smt.Update([]byte("testKey1"), []byte("testValue1"))
	if err != nil {
		t.Errorf("returned error when updating empty key: %v", err)
	}
	value, err = smt.Get([]byte("testKey1"))
	if err != nil {
		t.Errorf("returned error when getting non-empty key: %v", err)
	}
	if !bytes.Equal([]byte("testValue1"), value) {
		t.Error("did not get correct value when getting non-empty key")
	}
	if !bytes.Equal(root1, smt.Root()) {
		t.Error("tree root is not as expected after re-inserting key after deletion")
	}
}

func TestOrphanRemoval(t *testing.T) {
	var smn, smv *SimpleMap
	var smt *SparseMerkleTree
	var err error
	nodeCount := func() int {
		return len(smn.m)
	}

	setup := func() {
		hasher := sha256.New()
		smn, _ = NewSimpleMap(hasher.Size())
		smv, _ = NewSimpleMap(len([]byte("testKey1")))
		smt = NewSparseMerkleTree(smn, smv, hasher)
		_, err = smt.Update([]byte("testKey1"), []byte("testValue1"))
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
		_, err = smt.Delete([]byte("testKey1"))
		if err != nil {
			t.Errorf("returned error when updating non-empty key: %v", err)
		}
		if 0 != nodeCount() {
			t.Errorf("expected 0 nodes after deletion, got: %d", nodeCount())
		}
	})

	t.Run("overwrite 1", func(t *testing.T) {
		setup()
		_, err = smt.Update([]byte("testKey1"), []byte("testValue2"))
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

	newTestKey1 := make([]byte, len([]byte("testKey1")))
	newTestKey2 := make([]byte, len([]byte("testKey1")))
	copy(newTestKey1, "testKey1")
	copy(newTestKey2, "testKey1")

	newTestKey1[0] = byte(0b10000000) // key having zero common prefix with `testKey1`
	newTestKey2[0] = byte(0b01000000) // key having two common prefixes with `testKey1`

	cases := []testCase{
		{string(newTestKey1), 3}, // common prefix = 0, root + 2 leaves
		{string(newTestKey2), 5}, // common prefix = 2, root + 2 node branch + 2 leaves
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
			_, err = smt.Delete([]byte("testKey1"))
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
		_, err = smt.Update([]byte("testKey1"), []byte("testValue2"))
		if err != nil {
			t.Errorf("returned error when updating non-empty key: %v", err)
		}
		if 1 != nodeCount() {
			t.Errorf("expected 1 nodes after insertion, got: %d", nodeCount())
		}
		_, err = smt.Delete([]byte("testKey1"))
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
				t.Errorf("expected %d nodes after insertion, got: %d", tc.count, nodeCount())
			}
			_, err = smt.Update([]byte(tc.newKey), []byte("testValue3"))
			if err != nil {
				t.Errorf("returned error when updating non-empty key: %v", err)
			}
			if tc.count != nodeCount() {
				t.Errorf("expected %d nodes after insertion, got: %d", tc.count, nodeCount())
			}
			_, err = smt.Delete([]byte("testKey1"))
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
		_, err = smt.Update([]byte("testKey2"), []byte("testValue1"))
		if err != nil {
			t.Errorf("returned error when updating non-empty key: %v", err)
		}
		_, err = smt.Delete([]byte("testKey1"))
		if err != nil {
			t.Errorf("returned error when updating non-empty key: %v", err)
		}
		_, err = smt.Delete([]byte("testKey2"))
		if err != nil {
			t.Errorf("returned error when updating non-empty key: %v", err)
		}
	})
}
