// Package smt implements a Sparse Merkle tree.
package smt

import(
    "hash"
)

const left = 0
const right = 1

// SparseMerkleTree is a Sparse Merkle tree.
type SparseMerkleTree struct {
    defaultValue []byte
    depth int
    hasher hash.Hash
    ms MapStore
    root []byte
}

// Initialise a Sparse Merkle tree on an empty MapStore.
func NewSparseMerkleTree(ms MapStore, defaultValue []byte, depth int, hasher hash.Hash) *SparseMerkleTree {
    var currentValue, currentHash []byte
    hasher.Write(defaultValue)
    currentValue = hasher.Sum(nil)
    ms.Put(currentValue, defaultValue)
    for i := 0; i < depth; i++ {
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

// Get gets a key from the tree.
func (smt *SparseMerkleTree) Get(key []byte) ([]byte, error) {
    currentValue := make([]byte, len(smt.root))
    copy(currentValue, smt.root)

    for i := 0; i < smt.depth; i++ {
        value, err := smt.ms.Get(currentValue)
        if err != nil {
            return nil, err
        }
        if hasBit(key, i) == right {
            copy(currentValue, value[len(smt.root):])
        } else {
            copy(currentValue, value[:len(smt.root)])
        }
    }

    value, err := smt.ms.Get(currentValue)
    if err != nil {
        return nil, err
    }

    return value, nil
}

// Update sets a new value for a key in the tree.
func (smt *SparseMerkleTree) Update(key []byte, value []byte) error {
    sideNodes, err := smt.sideNodes(key)
    if err != nil {
        return err
    }

    currentValue := value
    smt.hasher.Write(currentValue)
    currentHash := smt.hasher.Sum(nil)
    smt.ms.Put(currentHash, currentValue)
    currentValue = currentHash

    for i := smt.depth - 1; i >= 0; i-- {
        sideNode := sideNodes[i]
        if hasBit(key, i) == right {
            currentValue = append(sideNode, currentValue...)
        } else {
            currentValue = append(currentValue, sideNode...)
        }
        smt.hasher.Write(currentValue)
        currentHash = smt.hasher.Sum(nil)
        err := smt.ms.Put(currentHash, currentValue)
        if err != nil {
            return err
        }
        currentValue = currentHash
    }

    smt.root = currentHash
    return nil
}

func (smt *SparseMerkleTree) sideNodes(key []byte) ([][]byte, error) {
    currentValue, err := smt.ms.Get(smt.root)
    if err != nil {
        return nil, err
    }

    sideNodes := make([][]byte, smt.depth)
    for i := 0; i < smt.depth; i++ {
        if hasBit(key, i) == right {
            sideNodes[i] = []byte(currentValue[:len(smt.root)])
            currentValue, err = smt.ms.Get(currentValue[len(smt.root):])
            if err != nil {
                return nil, err
            }
        } else {
            sideNodes[i] = []byte(currentValue[len(smt.root):])
            currentValue, err = smt.ms.Get(currentValue[:len(smt.root)])
            if err != nil {
                return nil, err
            }
        }
    }

    return sideNodes, err
}
