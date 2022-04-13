package smt

import (
	"bytes"
	"errors"
	"hash"
)

type SMT interface {
	Update(key, value []byte) ([]byte, error)
	Delete(key []byte) ([]byte, error)
	GetDescend(key []byte) ([]byte, error)
	hashValue([]byte) []byte

	Root() []byte
	Prove(key []byte) (SparseMerkleProof, error)
	ProveCompact(key []byte) (SparseCompactMerkleProof, error)
}

type SMTWithStorage struct {
	SMT
	preimages MapStore
}

// NewSparseMerkleTree creates a new Sparse Merkle tree on an empty MapStore.
func NewSMTWithStorage(nodes, preimages MapStore, hasher hash.Hash) *SMTWithStorage {
	return &SMTWithStorage{
		SMT:       NewSparseMerkleTree(nodes, hasher),
		preimages: preimages,
	}
}

// ImportSparseMerkleTree imports a Sparse Merkle tree from a non-empty MapStore.
func ImportSMTWithStorage(nodes, preimages MapStore, hasher hash.Hash, root []byte) *SMTWithStorage {
	return &SMTWithStorage{
		SMT:       ImportSparseMerkleTree(nodes, hasher, root),
		preimages: preimages,
	}
}

func (smt *SMTWithStorage) Update(key []byte, value []byte) ([]byte, error) {
	r, err := smt.SMT.Update(key, value)
	if err != nil {
		return nil, err
	}
	valueHash := smt.SMT.hashValue(value)
	err = smt.preimages.Set(valueHash, value)
	if err != nil {
		return nil, err
	}
	return r, err
}

func (smt *SMTWithStorage) Delete(key []byte) ([]byte, error) {
	r, err := smt.SMT.Delete(key)
	if err != nil {
		return nil, err
	}
	return r, nil
}

// Get gets the value of a key from the tree.
func (smt *SMTWithStorage) Get(key []byte) ([]byte, error) {
	valueHash, err := smt.SMT.GetDescend(key)
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
	val, err := smt.Get(key)
	return !bytes.Equal(defaultValue, val), err
}

func (smt *SparseMerkleTree) hashValue(value []byte) []byte {
	return smt.th.digest(value)
}
