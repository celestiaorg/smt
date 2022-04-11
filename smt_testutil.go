package smt

import (
	"bytes"
	"errors"
	"hash"
)

type SMTWithStorage struct {
	*SparseMerkleTree
	preimages MapStore
}

// NewSparseMerkleTree creates a new Sparse Merkle tree on an empty MapStore.
func NewSMTWithStorage(nodes, preimages MapStore, hasher hash.Hash) *SMTWithStorage {
	return &SMTWithStorage{
		SparseMerkleTree: NewSparseMerkleTree(nodes, hasher),
		preimages:        preimages,
	}
}

// ImportSparseMerkleTree imports a Sparse Merkle tree from a non-empty MapStore.
func ImportSMTWithStorage(nodes, preimages MapStore, hasher hash.Hash, root []byte) *SMTWithStorage {
	return &SMTWithStorage{
		SparseMerkleTree: ImportSparseMerkleTree(nodes, hasher, root),
		preimages:        preimages,
	}
}

func (smt *SMTWithStorage) Update(key []byte, value []byte) ([]byte, error) {
	r, err := smt.SparseMerkleTree.Update(key, value)
	if err != nil {
		return nil, err
	}
	valueHash := smt.th.digest(value)
	err = smt.preimages.Set(valueHash, value)
	if err != nil {
		return nil, err
	}
	return r, err
}

func (smt *SMTWithStorage) Delete(key []byte) ([]byte, error) {
	r, err := smt.SparseMerkleTree.Delete(key)
	if err != nil {
		return nil, err
	}
	return r, nil
}

// Get gets the value of a key from the tree.
func (smt *SMTWithStorage) Get(key []byte) ([]byte, error) {
	valueHash, err := smt.GetDescend(key)
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

// GetDescend gets the value of a key from the tree by descending it.
func (smt *SparseMerkleTree) GetDescend(key []byte) ([]byte, error) {
	// Get tree's root
	root := smt.Root()

	if bytes.Equal(root, smt.th.placeholder()) {
		// The tree is empty, return the default value.
		return defaultValue, nil
	}

	path := smt.th.path(key)
	currentHash := root
	for i := 0; i < smt.depth(); i++ {
		currentData, err := smt.nodes.Get(currentHash)
		if err != nil {
			return nil, err
		} else if smt.th.isLeaf(currentData) {
			// We've reached the end. Is this the actual leaf?
			p, valueHash := smt.th.parseLeaf(currentData)
			if !bytes.Equal(path, p) {
				// Nope. Therefore the key is actually empty.
				return defaultValue, nil
			}
			// Otherwise, yes. Return the value.
			return valueHash, nil
		}

		leftNode, rightNode := smt.th.parseNode(currentData)
		if getBitAtFromMSB(path, i) == right {
			currentHash = rightNode
		} else {
			currentHash = leftNode
		}

		if bytes.Equal(currentHash, smt.th.placeholder()) {
			// We've hit a placeholder value; this is the end.
			return defaultValue, nil
		}
	}

	// This should only be reached if the path is 256 bits long.
	currentData, err := smt.nodes.Get(currentHash)
	if err != nil {
		return nil, err
	}
	_, valueHash := smt.th.parseLeaf(currentData)
	return valueHash, nil
}

// HasDescend returns true iff the value at the given key is non-default.
// Errors if the key cannot be reached by descending.
func (smt *SparseMerkleTree) HasDescend(key []byte) (bool, error) {
	val, err := smt.GetDescend(key)
	if err != nil {
		return false, err
	}
	return !bytes.Equal(defaultValue, val), nil
}
