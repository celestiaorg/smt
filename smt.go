// Package smt implements a Sparse Merkle tree.
package smt

import (
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
    for _, b := range key {
        path = (path << 8) + int(b)
        //fmt.Printf("path: %x\n",path)
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

func (smt *SparseMerkleTree) Update(key []byte, value []byte) (error) {
    currentValue := make([]byte, len(smt.root))
    copy(currentValue, smt.root)
    path1 := keyToPath(key)
    path2 := keyToPath(key)

    sidenodes := make([][]byte, smt.depth)
    for i := uint(0); i < smt.depth; i++ {
        v, err := smt.ms.Get(currentValue)
        if err != nil {
            return err
        }
        if (path1 >> 255) & 1 == 1 {
            copy(currentValue, v[32:])
            sidenodes[i] = make([]byte, len(smt.root))
            copy(sidenodes[i], v[:32])
        } else {
            copy(currentValue, v[:32])
            sidenodes[i] = make([]byte, len(smt.root))
            copy(sidenodes[i], v[32:])
        }
        path1 <<= 1
    }
    currentValue = value

    var currentHash []byte
    for i := uint(0); i < smt.depth; i++ {
        if path2 & 1 == 1 {
            currentValue = append(sidenodes[len(sidenodes)-1], currentValue...)
        } else {
            currentValue = append(currentValue, sidenodes[len(sidenodes)-1]...)
        }
        smt.hasher.Write(currentValue)
        currentHash = smt.hasher.Sum(nil)
        //fmt.Printf("key: %x\n",currentHash)
        //fmt.Printf("value: %x\n",currentValue)
        smt.ms.Put(currentHash, currentValue)

        currentValue = make([]byte, len(currentHash))
        copy(currentValue, currentHash)
        sidenodes = sidenodes[:len(sidenodes)-1]
        path2 >>= 1
    }
    smt.root = currentHash

    return nil
}
