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
    root []byte
}

// Initialise a Sparse Merkle tree on an empty MapStore.
func NewSparseMerkleTree(ms MapStore, defaultValue []byte, depth uint, hasher hash.Hash) *SparseMerkleTree {
    var currentValue, currentHash []byte
    hasher.Write(defaultValue)
    currentValue = hasher.Sum(nil)
    ms.Put(currentValue, defaultValue)
    for i := uint(0); i < depth; i++ {
        currentValue = append(currentValue, currentValue...)
        hasher.Write(currentValue)
        currentHash = hasher.Sum(nil)
        ms.Put(currentHash, currentValue)
        currentValue = make([]byte, len(currentHash))
        copy(currentValue, currentHash)
    }
    return &SparseMerkleTree{
        defaultValue: defaultValue,
        depth: depth,
        hasher: hasher,
        ms: ms,
        root: currentHash,
    }
}

func keyToPath(key []byte) int {
    path := 0
    for _, b := range(key) {
        path = (path << 8) + int(b)
    }

    return path
}

func (smt *SparseMerkleTree) Get(key []byte) ([]byte, error) {
    // TODO: don't hardcode length of keys
    currentValue := make([]byte, len(smt.root))
    copy(currentValue, smt.root)
    path := keyToPath(key)

    for i := uint(0); i < smt.depth; i++ {
        value, err := smt.ms.Get(currentValue)
        if err != nil {
            return nil, err
        }
        if (path >> 255) & 1 == 1 {
            copy(currentValue, value[32:])
        } else {
            copy(currentValue, value[:32])
        }
        path <<= 1
    }

    value, err := smt.ms.Get(currentValue)
    if err != nil {
        return nil, err
    }

    return value, nil
}
