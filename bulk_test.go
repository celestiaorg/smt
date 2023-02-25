package smt

import (
	"bytes"
	"crypto/sha256"
	"math/rand"
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"
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
func bulkOperations(t *testing.T, operations, insert, update, delete int) (*SparseMerkleTree, *SimpleMap, *SimpleMap, map[string]string) {
	smn, smv := NewSimpleMap(), NewSimpleMap()
	smt := NewSparseMerkleTree(smn, smv, sha256.New())

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

		bulkCheckAll(t, smt, kv)
	}
	return smt, smn, smv, kv
}

func bulkCheckAll(t *testing.T, smt *SparseMerkleTree, kv map[string]string) {
	for k, v := range kv {
		value, err := smt.Get([]byte(k))
		if err != nil {
			t.Errorf("error: %v", err)
		}
		if !bytes.Equal([]byte(v), value) {
			t.Error("got incorrect value when bulk testing operations")
		}

		// Generate and verify a Merkle proof for this key.
		proof, err := smt.Prove([]byte(k))
		if err != nil {
			t.Errorf("error: %v", err)
		}
		if !VerifyProof(proof, smt.Root(), []byte(k), []byte(v), smt.th.hasher) {
			t.Error("Merkle proof failed to verify")
		}
		compactProof, err := smt.ProveCompact([]byte(k))
		if err != nil {
			t.Errorf("error: %v", err)
		}
		if !VerifyCompactProof(compactProof, smt.Root(), []byte(k), []byte(v), smt.th.hasher) {
			t.Error("Merkle proof failed to verify")
		}

		if v == "" {
			continue
		}

		// Check that the key is at the correct height in the tree.
		largestCommonPrefix := getLargestCommonPrefix(t, smt, kv, k)
		numSideNodes := getNumSideNodes(t, smt, kv, k)
		if (numSideNodes != largestCommonPrefix+1) && numSideNodes != 0 && largestCommonPrefix != 0 {
			t.Error("leaf is at unexpected height")
		}
	}
}

func getNumSideNodes(t *testing.T, smt *SparseMerkleTree, kv map[string]string, key string) (numSideNodes int) {
	path := smt.th.path([]byte(key))
	sideNodes, _, _, _, err := smt.sideNodesForRoot(path, smt.Root())
	require.NoError(t, err)
	for _, v := range sideNodes {
		if v != nil {
			numSideNodes++
		}
	}
	return
}

func getLargestCommonPrefix(_ *testing.T, smt *SparseMerkleTree, kv map[string]string, key string) (largestCommonPrefix int) {
	path := smt.th.path([]byte(key))
	for k, v := range kv {
		if v == "" {
			continue
		}
		commonPrefix := countCommonPrefix(path, smt.th.path([]byte(k)))
		if commonPrefix != smt.depth() && commonPrefix > largestCommonPrefix {
			largestCommonPrefix = commonPrefix
		}
	}
	return
}
