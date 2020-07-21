package smt

import (
	"bytes"
	"crypto/sha256"
	"math/rand"
	"reflect"
	"testing"
)

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
		sideNodes, _, _, err := smt.sideNodesForRoot(smt.th.path([]byte(k)), smt.Root())
		if err != nil {
			t.Errorf("error: %v", err)
		}
		numSideNodes := 0
		for _, v := range sideNodes {
			if v != nil {
				numSideNodes += 1
			}
		}
		if numSideNodes != largestCommonPrefix+1 && (numSideNodes != 0 && largestCommonPrefix != 0) {
			t.Error("leaf is at unexpected height")
		}
	}
}
