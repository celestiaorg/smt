package smt

import (
	"bytes"
	"crypto/sha256"
	"math/rand"
	"reflect"
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

	// Test updating a second empty key where the path for both keys start with different bits (when using SHA256).
	_, err = smt.Update([]byte("foo"), []byte("testValue"))
	if err != nil {
		t.Errorf("returned error when updating empty second key: %v", err)
	}
	value, err = smt.Get([]byte("foo"))
	if err != nil {
		t.Errorf("returned error when getting non-empty second key: %v", err)
	}
	if bytes.Compare([]byte("testValue"), value) != 0 {
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
	if bytes.Compare([]byte("testValue"), value) != 0 {
		t.Error("did not get correct value when getting non-empty third key")
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
	_, err = smt.Update([]byte("testKey"), []byte("testValue"))
	if err != nil {
		t.Errorf("returned error when updating empty key: %v", err)
	}
	root1 := smt.Root()
	_, err = smt.Update([]byte("testKey"), defaultValue)
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
	if !bytes.Equal(root1, smt.Root()) {
		t.Error("tree root is not as expected after deleting second key")
	}

	// Test inserting and deleting a different second key, when the the first bits of the path for the two keys in the tree are different (when using SHA256).
	_, err = smt.Update([]byte("foo"), []byte("testValue"))
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
	if !bytes.Equal(root1, smt.Root()) {
		t.Error("tree root is not as expected after deleting second key")
	}
}

// Test all tree operations in bulk.
func TestSparseMerkleTree(t *testing.T) {
	for i := 0; i < 5; i++ {
		// Test more inserts/updates than deletions.
		bulkOperations(t, 200, 100, 100, 50)
	}
	for i := 0; i < 5; i++ {
		// Test extreme deletions.
		bulkOperations(t, 200, 100, 100, 500)
	}
}

// Test all tree operations in bulk, with specified ratio probabilities of insert, update and delete.
func bulkOperations(t *testing.T, operations int, insert int, update int, delete int) {
	sm := NewSimpleMap()
	smt := NewSparseMerkleTree(sm, sha256.New())

	max := insert + update + delete
	kv := make(map[string]string)

	for i := 0; i < operations; i++ {
		n := rand.Intn(max)
		if n < insert { // Insert
			keyLen := 16 + rand.Intn(32)
			key := make([]byte, keyLen)
			rand.Read(key)

			valLen := 1 + rand.Intn(64)
			val := make([]byte, valLen)
			rand.Read(val)

			kv[string(key)] = string(val)
			_, err := smt.Update(key, val)
			if err != nil {
				t.Errorf("error: %v", err)
			}
		} else if n > insert && n < insert+update { // Update
			keys := reflect.ValueOf(kv).MapKeys()
			if len(keys) == 0 {
				continue
			}
			key := []byte(keys[rand.Intn(len(keys))].Interface().(string))

			valLen := 1 + rand.Intn(64)
			val := make([]byte, valLen)
			rand.Read(val)

			kv[string(key)] = string(val)
			_, err := smt.Update(key, val)
			if err != nil {
				t.Errorf("error: %v", err)
			}
		} else { // Delete
			keys := reflect.ValueOf(kv).MapKeys()
			if len(keys) == 0 {
				continue
			}
			key := []byte(keys[rand.Intn(len(keys))].Interface().(string))

			kv[string(key)] = ""
			_, err := smt.Update(key, defaultValue)
			if err != nil {
				t.Errorf("error: %v", err)
			}
		}

		bulkCheckAll(t, smt, &kv)
	}
}

func bulkCheckAll(t *testing.T, smt *SparseMerkleTree, kv *map[string]string) {
	for k, v := range *kv {
		value, err := smt.Get([]byte(k))
		if err != nil {
			t.Errorf("error: %v", err)
		}
		if !bytes.Equal([]byte(v), value) {
			t.Error("got incorrect value when bulk testing operations")
		}

		if v == "" {
			continue
		}

		// Check that the key is at the correct height in the tree.
		largestCommonPrefix := 0
		for k2, v2 := range *kv {
			if v2 == "" {
				continue
			}
			commonPrefix := countCommonPrefix(smt.th.path([]byte(k)), smt.th.path([]byte(k2)))
			if commonPrefix != smt.depth() && commonPrefix > largestCommonPrefix {
				largestCommonPrefix = commonPrefix
			}
		}
		sideNodes, _, _, _ := smt.sideNodesForRoot(smt.th.path([]byte(k)), smt.Root())
		numSideNodes := 0
		for _, v := range sideNodes {
			if v != nil {
				numSideNodes += 1
			}
		}
		if numSideNodes != largestCommonPrefix + 1 && (numSideNodes != 0 && largestCommonPrefix != 0) {
			t.Error("leaf is at unexpected height")
		}
	}
}
