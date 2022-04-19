package smt

import (
	"bytes"
	"crypto/sha256"
	"math/rand"
	"testing"
)

// Test all tree operations in bulk.
func TestBulkOperations(t *testing.T) {
	for i := 0; i < 5; i++ {
		// Test more inserts/updates than deletions.
		bulkOperations(t, 200, 100, 100, 50)
	}
	for i := 0; i < 5; i++ {
		// Test extreme deletions.
		bulkOperations(t, 200, 100, 100, 500)
	}
}

type bulkop struct{ key, val []byte }

// Test all tree operations in bulk, with specified ratio probabilities of insert, update and delete.
func bulkOperations(t *testing.T, operations int, insert int, update int, delete int) {
	smn, smv := NewSimpleMap(), NewSimpleMap()
	smt := NewSMTWithStorage(smn, smv, sha256.New())

	max := insert + update + delete
	var kv []bulkop

	for i := 0; i < operations; i++ {
		n := rand.Intn(max)
		if n < insert { // Insert
			keyLen := 16 + rand.Intn(32)
			key := make([]byte, keyLen)
			rand.Read(key)

			valLen := 1 + rand.Intn(64)
			val := make([]byte, valLen)
			rand.Read(val)

			err := smt.Update(key, val)
			if err != nil {
				t.Fatalf("error: %v", err)
			}
			kv = append(kv, bulkop{key, val})
		} else if n > insert && n < insert+update { // Update
			if len(kv) == 0 {
				continue
			}
			ki := rand.Intn(len(kv))
			valLen := 1 + rand.Intn(64)
			val := make([]byte, valLen)
			rand.Read(val)

			err := smt.Update(kv[ki].key, val)
			if err != nil {
				t.Fatalf("error: %v", err)
			}
			kv[ki].val = val
		} else { // Delete
			if len(kv) == 0 {
				continue
			}
			ki := rand.Intn(len(kv))

			err := smt.Delete(kv[ki].key)
			if err != nil && err != ErrKeyNotPresent {
				t.Fatalf("error: %v", err)
			}
			kv[ki].val = nil
		}
		bulkCheckAll(t, smt, kv)
	}
}

func bulkCheckAll(t *testing.T, smt *SMTWithStorage, kv []bulkop) {
	for ki := range kv {
		k, v := kv[ki].key, kv[ki].val

		value, err := smt.GetValue([]byte(k))
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
		if !VerifyProof(proof, smt.Root(), []byte(k), []byte(v), smt.base()) {
			t.Error("Merkle proof failed to verify:", []byte(k))
		}
		compactProof, err := ProveCompact([]byte(k), smt)
		if err != nil {
			t.Errorf("error: %v", err)
		}
		if !VerifyCompactProof(compactProof, smt.Root(), []byte(k), []byte(v), smt.base()) {
			t.Error("Merkle proof failed to verify")
		}

		if v == nil {
			continue
		}

		// Check that the key is at the correct height in the tree.
		largestCommonPrefix := 0
		for ki2 := range kv {
			k2, v2 := kv[ki2].key, kv[ki2].val
			if v2 == nil {
				continue
			}

			ph := smt.base().ph
			commonPrefix := countCommonPrefix(ph.Path([]byte(k)), ph.Path([]byte(k2)))
			if commonPrefix != smt.base().depth() && commonPrefix > largestCommonPrefix {
				largestCommonPrefix = commonPrefix
			}
		}
		numSideNodes := 0
		for _, v := range proof.SideNodes {
			if v != nil {
				numSideNodes++
			}
		}
		if numSideNodes != largestCommonPrefix+1 && (numSideNodes != 0 && largestCommonPrefix != 0) {
			t.Error("leaf is at unexpected height")
		}
	}
}
