// Package smt implements a Sparse Merkle tree.
package smt

import(
    "hash"
)

// SparseMerkleTree is a Sparse Merkle tree.
type SparseMerkleTree struct {
    defaultValue []byte
    depth uint
    hasher hash.Hash
    ms MapStore
}

// Initialise a Sparse Merkle tree on an empty MapStore.
func NewSparseMerkleTree(ms MapStore, defaultValue []byte, depth uint, hasher hash.Hash) []byte {
    var currentValue, currentHash []byte
    currentValue = defaultValue
    for i := uint(0); i < depth; i++ {
        currentValue = append(currentValue, currentValue...)
        hasher.Write(currentValue)
        currentHash = hasher.Sum(nil)
        ms.Put(currentHash, currentValue)
        currentValue = make([]byte, len(currentHash))
        copy(currentValue, currentHash)
    }
    return currentHash
}
