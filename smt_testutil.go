package smt

import (
	"bytes"
	"errors"
)

// SMTWithStorage Wraps an SMT with a mapping of value hashes to values (preimages), for use in tests.
// Note: this doesn't delete from preimages, since there could be duplicate stored values.
type SMTWithStorage struct {
	*SMT
	preimages MapStore
}

func (smt *SMTWithStorage) Update(key []byte, value []byte) error {
	err := smt.SMT.Update(key, value)
	if err != nil {
		return err
	}
	valueHash := smt.digestValue(value)
	err = smt.preimages.Set(valueHash, value)
	if err != nil {
		return err
	}
	return err
}

func (smt *SMTWithStorage) Delete(key []byte) error {
	err := smt.SMT.Delete(key)
	if err != nil {
		return err
	}
	return nil
}

// Get gets the value of a key from the tree.
func (smt *SMTWithStorage) GetValue(key []byte) ([]byte, error) {
	valueHash, err := smt.SMT.Get(key)
	if err != nil {
		return nil, err
	}
	value, err := smt.preimages.Get(valueHash)
	if err != nil {
		var invalidKeyError *InvalidKeyError
		if errors.As(err, &invalidKeyError) {
			// If key isn't found, return default value
			value = defaultValue
		} else {
			// Otherwise percolate up any other error
			return nil, err
		}
	}
	return value, nil
}

// Has returns true if the value at the given key is non-default, false
// otherwise.
func (smt *SMTWithStorage) Has(key []byte) (bool, error) {
	val, err := smt.GetValue(key)
	return !bytes.Equal(defaultValue, val), err
}

// ProveCompact generates a compacted Merkle proof for a key against the current root.
func ProveCompact(key []byte, smt SparseMerkleTree) (SparseCompactMerkleProof, error) {
	proof, err := smt.Prove(key)
	if err != nil {
		return SparseCompactMerkleProof{}, err
	}
	return CompactProof(proof, smt.Spec())
}

// dummyHasher is a dummy hasher for tests, where the digest of keys is equivalent to the preimage.
type dummyPathHasher struct {
	size int
}

func (h dummyPathHasher) Path(key []byte) []byte {
	if len(key) != h.size {
		panic("len(key) must equal path size")
	}
	return key
}

func (h dummyPathHasher) PathSize() int { return h.size }
