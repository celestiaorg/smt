package smt

import (
	"crypto/sha256"
	"hash"
	"math/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

func NewSMTWithStorage(nodes, preimages MapStore, hasher hash.Hash, options ...Option) *SMTWithStorage {
	return &SMTWithStorage{
		SMT:       NewSparseMerkleTree(nodes, hasher, options...),
		preimages: preimages,
	}
}

func TestTreeUpdateBasic(t *testing.T) {
	smn, smv := NewSimpleMap(), NewSimpleMap()
	lazy := NewSparseMerkleTree(smn, sha256.New())
	smt := &SMTWithStorage{SMT: lazy, preimages: smv}
	var value []byte
	var has bool
	var err error

	// Test getting an empty key.
	value, err = smt.GetValue([]byte("testKey"))
	require.NoError(t, err)
	require.Equal(t, defaultValue, value)

	has, err = smt.Has([]byte("testKey"))
	require.NoError(t, err)
	require.False(t, has)

	// Test updating the empty key.
	err = smt.Update([]byte("testKey"), []byte("testValue"))
	require.NoError(t, err)

	value, err = smt.GetValue([]byte("testKey"))
	require.NoError(t, err)
	require.Equal(t, []byte("testValue"), value)

	has, err = smt.Has([]byte("testKey"))
	require.NoError(t, err)
	require.True(t, has)

	// Test updating the non-empty key.
	err = smt.Update([]byte("testKey"), []byte("testValue2"))
	require.NoError(t, err)

	value, err = smt.GetValue([]byte("testKey"))
	require.NoError(t, err)
	require.Equal(t, []byte("testValue2"), value)

	// Test updating a second empty key where the path for both keys share the
	// first 2 bits (when using SHA256).
	err = smt.Update([]byte("foo"), []byte("testValue"))
	require.NoError(t, err)

	value, err = smt.GetValue([]byte("foo"))
	require.NoError(t, err)
	require.Equal(t, []byte("testValue"), value)

	// Test updating a third empty key.
	err = smt.Update([]byte("testKey2"), []byte("testValue"))
	require.NoError(t, err)

	value, err = smt.GetValue([]byte("testKey2"))
	require.NoError(t, err)
	require.Equal(t, []byte("testValue"), value)

	value, err = smt.GetValue([]byte("testKey"))
	require.NoError(t, err)
	require.Equal(t, []byte("testValue2"), value)

	require.NoError(t, lazy.Commit())

	// Test that a tree can be imported from a MapStore.
	lazy = ImportSparseMerkleTree(smn, sha256.New(), smt.Root())
	require.NoError(t, err)
	smt = &SMTWithStorage{SMT: lazy, preimages: smv}

	value, err = smt.GetValue([]byte("testKey"))
	require.NoError(t, err)
	require.Equal(t, []byte("testValue2"), value)

	value, err = smt.GetValue([]byte("foo"))
	require.NoError(t, err)
	require.Equal(t, []byte("testValue"), value)

	value, err = smt.GetValue([]byte("testKey2"))
	require.NoError(t, err)
	require.Equal(t, []byte("testValue"), value)
}

// Test base case tree delete operations with a few keys.
func TestTreeDeleteBasic(t *testing.T) {
	smn, smv := NewSimpleMap(), NewSimpleMap()
	lazy := NewSparseMerkleTree(smn, sha256.New())
	smt := &SMTWithStorage{SMT: lazy, preimages: smv}
	rootEmpty := smt.Root()

	// Testing inserting, deleting a key, and inserting it again.
	err := smt.Update([]byte("testKey"), []byte("testValue"))
	require.NoError(t, err)

	root1 := smt.Root()
	err = smt.Delete([]byte("testKey"))
	require.NoError(t, err)

	value, err := smt.GetValue([]byte("testKey"))
	require.NoError(t, err)
	require.Equal(t, defaultValue, value, "getting deleted key")

	has, err := smt.Has([]byte("testKey"))
	require.NoError(t, err)
	require.False(t, has, "checking existernce of deleted key")

	err = smt.Update([]byte("testKey"), []byte("testValue"))
	require.NoError(t, err)

	value, err = smt.GetValue([]byte("testKey"))
	require.NoError(t, err)
	require.Equal(t, []byte("testValue"), value)
	require.Equal(t, root1, smt.Root(), "re-inserting key after deletion")

	// Test inserting and deleting a second key.
	err = smt.Update([]byte("testKey2"), []byte("testValue"))
	require.NoError(t, err)

	err = smt.Delete([]byte("testKey2"))
	require.NoError(t, err)

	value, err = smt.GetValue([]byte("testKey2"))
	require.NoError(t, err)
	require.Equal(t, defaultValue, value, "getting deleted key")

	value, err = smt.GetValue([]byte("testKey"))
	require.NoError(t, err)
	require.Equal(t, []byte("testValue"), value)
	require.Equal(t, root1, smt.Root(), "after deleting second key")

	// Test inserting and deleting a different second key, when the the first 2
	// bits of the path for the two keys in the tree are the same (when using SHA256).
	err = smt.Update([]byte("foo"), []byte("testValue"))
	require.NoError(t, err)

	value, err = smt.GetValue([]byte("foo"))
	require.NoError(t, err)

	err = smt.Delete([]byte("foo"))
	require.NoError(t, err)

	value, err = smt.GetValue([]byte("foo"))
	require.NoError(t, err)
	require.Equal(t, defaultValue, value, "getting deleted key")

	value, err = smt.GetValue([]byte("testKey"))
	require.NoError(t, err)
	require.Equal(t, []byte("testValue"), value)
	require.Equal(t, root1, smt.Root(), "after deleting second key")

	// Testing inserting, deleting a key, and inserting it again
	err = smt.Update([]byte("testKey"), []byte("testValue"))
	require.NoError(t, err)

	root1 = smt.Root()
	err = smt.Delete([]byte("testKey"))
	require.NoError(t, err)

	// Fail to delete an absent key, but leave tree in a valid state
	err = smt.Delete([]byte("testKey"))
	require.Error(t, err)

	value, err = smt.GetValue([]byte("testKey"))
	require.NoError(t, err)
	require.Equal(t, defaultValue, value, "getting deleted key")

	has, err = smt.Has([]byte("testKey"))
	require.NoError(t, err)
	require.False(t, has, "checking existernce of deleted key")
	require.Equal(t, rootEmpty, smt.Root())

	err = smt.Update([]byte("testKey"), []byte("testValue"))
	require.NoError(t, err)

	value, err = smt.GetValue([]byte("testKey"))
	require.NoError(t, err)
	require.Equal(t, []byte("testValue"), value)
	require.Equal(t, root1, smt.Root(), "re-inserting key after deletion")
}

// Test tree ops with known paths
func TestTreeKnownPath(t *testing.T) {
	ph := dummyPathHasher{32}
	smn, smv := NewSimpleMap(), NewSimpleMap()
	smt := NewSMTWithStorage(smn, smv, sha256.New(), WithPathHasher(ph))
	var value []byte
	var err error

	baseKey := make([]byte, ph.PathSize())
	keys := make([][]byte, 7)
	for i, _ := range keys {
		keys[i] = make([]byte, ph.PathSize())
		copy(keys[i], baseKey)
	}
	keys[0][0] = byte(0b00000000)
	keys[1][0] = byte(0b00100000)
	keys[2][0] = byte(0b10000000)
	keys[3][0] = byte(0b11000000)
	keys[4][0] = byte(0b11010000)
	keys[5][0] = byte(0b11100000)
	keys[6][0] = byte(0b11110000)

	err = smt.Update(keys[0], []byte("testValue1"))
	require.NoError(t, err)
	err = smt.Update(keys[1], []byte("testValue2"))
	require.NoError(t, err)
	err = smt.Update(keys[2], []byte("testValue3"))
	require.NoError(t, err)
	err = smt.Update(keys[3], []byte("testValue4"))
	require.NoError(t, err)
	err = smt.Update(keys[4], []byte("testValue5"))
	require.NoError(t, err)
	err = smt.Update(keys[5], []byte("testValue6"))
	require.NoError(t, err)

	value, err = smt.GetValue(keys[0])
	require.NoError(t, err)
	require.Equal(t, []byte("testValue1"), value)

	value, err = smt.GetValue(keys[1])
	require.NoError(t, err)
	require.Equal(t, []byte("testValue2"), value)

	value, err = smt.GetValue(keys[2])
	require.NoError(t, err)
	require.Equal(t, []byte("testValue3"), value)

	value, err = smt.GetValue(keys[3])
	require.NoError(t, err)
	require.Equal(t, []byte("testValue4"), value)

	err = smt.Delete(keys[3])
	require.NoError(t, err)

	value, err = smt.GetValue(keys[4])
	require.NoError(t, err)
	require.Equal(t, []byte("testValue5"), value)

	value, err = smt.GetValue(keys[5])
	require.NoError(t, err)
	require.Equal(t, []byte("testValue6"), value)

	// Fail to delete an absent key with a leaf where it would be
	err = smt.Delete(keys[6])
	require.Error(t, err)
	// Key at would-be position is still accessible
	value, err = smt.GetValue(keys[5])
	require.NoError(t, err)
	require.Equal(t, []byte("testValue6"), value)
}

// Test tree operations when two leafs are immediate neighbors.
func TestTreeMaxHeightCase(t *testing.T) {
	ph := dummyPathHasher{32}
	smn, smv := NewSimpleMap(), NewSimpleMap()
	smt := NewSMTWithStorage(smn, smv, sha256.New(), WithPathHasher(ph))
	var value []byte
	var err error

	// Make two neighboring keys.
	// The dummy hash function will return the preimage itself as the digest.
	key1 := make([]byte, ph.PathSize())
	key2 := make([]byte, ph.PathSize())
	rand.Read(key1)
	copy(key2, key1)
	// We make key2's least significant bit different than key1's
	key1[ph.PathSize()-1] = byte(0)
	key2[ph.PathSize()-1] = byte(1)

	err = smt.Update(key1, []byte("testValue1"))
	require.NoError(t, err)

	err = smt.Update(key2, []byte("testValue2"))
	require.NoError(t, err)

	value, err = smt.GetValue(key1)
	require.NoError(t, err)
	require.Equal(t, []byte("testValue1"), value)

	value, err = smt.GetValue(key2)
	require.NoError(t, err)
	require.Equal(t, []byte("testValue2"), value)

	proof, err := smt.Prove(key1)
	require.NoError(t, err)
	require.Equal(t, 256, len(proof.SideNodes), "unexpected proof size")
}

func TestOrphanRemoval(t *testing.T) {
	var smn, smv *SimpleMap
	var impl *SMT
	var smt *SMTWithStorage
	var err error

	nodeCount := func(t *testing.T) int {
		require.NoError(t, impl.Commit())
		return len(smn.m)
	}
	setup := func() {
		smn, smv = NewSimpleMap(), NewSimpleMap()
		impl = NewSparseMerkleTree(smn, sha256.New())
		smt = &SMTWithStorage{SMT: impl, preimages: smv}

		err = smt.Update([]byte("testKey"), []byte("testValue"))
		require.NoError(t, err)
		require.Equal(t, 1, nodeCount(t)) // only root node
	}

	t.Run("delete 1", func(t *testing.T) {
		setup()
		err = smt.Delete([]byte("testKey"))
		require.NoError(t, err)
		require.Equal(t, 0, nodeCount(t))
	})

	t.Run("overwrite 1", func(t *testing.T) {
		setup()
		err = smt.Update([]byte("testKey"), []byte("testValue2"))
		require.NoError(t, err)
		require.Equal(t, 1, nodeCount(t))
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
		{[]string{"foo"}, 4},
		{[]string{"testKey2", "foo"}, 6},
		{[]string{"a", "b", "c", "d", "e"}, 14},
	}

	t.Run("overwrite and delete", func(t *testing.T) {
		setup()
		err = smt.Update([]byte("testKey"), []byte("testValue2"))
		require.NoError(t, err)
		require.Equal(t, 1, nodeCount(t))

		err = smt.Delete([]byte("testKey"))
		require.NoError(t, err)
		require.Equal(t, 0, nodeCount(t))

		for tci, tc := range cases {
			setup()
			for _, key := range tc.keys {
				err = smt.Update([]byte(key), []byte("testValue2"))
				require.NoError(t, err, tci)
			}
			require.Equal(t, tc.count, nodeCount(t), tci)

			// Overwrite doesn't change count
			for _, key := range tc.keys {
				err = smt.Update([]byte(key), []byte("testValue3"))
				require.NoError(t, err, tci)
			}
			require.Equal(t, tc.count, nodeCount(t), tci)

			// Deletion removes all nodes except root
			for _, key := range tc.keys {
				err = smt.Delete([]byte(key))
				require.NoError(t, err, tci)
			}
			require.Equal(t, 1, nodeCount(t), tci)

			// Deleting and re-inserting a persisted node doesn't change count
			require.NoError(t, smt.Delete([]byte("testKey")))
			require.NoError(t, smt.Update([]byte("testKey"), []byte("testValue")))
			require.Equal(t, 1, nodeCount(t), tci)
		}
	})
}
