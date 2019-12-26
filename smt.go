// Package smt implements a Sparse Merkle tree.
package smt

import(
    "hash"
)

const left = 0
const right = 1
const nodePrefix byte = 0
const leafPrefix byte = 1
var defaultValue = []byte{0}

// SparseMerkleTree is a Sparse Merkle tree.
type SparseMerkleTree struct {
    hasher hash.Hash
    ms MapStore
    root []byte
}

// NewSparseMerkleTree creates a new Sparse Merkle tree on an empty MapStore.
func NewSparseMerkleTree(ms MapStore, hasher hash.Hash) *SparseMerkleTree {
    smt := SparseMerkleTree{
        hasher: hasher,
        ms: ms,
    }

    for i := 0; i < smt.depth() - 1; i++ {
        ms.Put(smt.defaultNode(i), append(smt.defaultNode(i + 1), smt.defaultNode(i + 1)...))
    }

    ms.Put(smt.defaultNode(255), defaultValue)

    rootValue := append(smt.defaultNode(0), smt.defaultNode(0)...)
    rootHash := smt.digestNode(rootValue)
    ms.Put(rootHash, rootValue)
    smt.SetRoot(rootHash)

    return &smt
}

// ImportSparseMerkleTree imports a Sparse Merkle tree from a non-empty MapStore.
func ImportSparseMerkleTree(ms MapStore, hasher hash.Hash, root []byte) *SparseMerkleTree {
    smt := SparseMerkleTree{
        hasher: hasher,
        ms: ms,
        root: root,
    }
    return &smt
}

// Root gets the root of the tree.
func (smt *SparseMerkleTree) Root() []byte {
    return smt.root
}

// SetRoot sets the root of the tree.
func (smt *SparseMerkleTree) SetRoot(root []byte) {
    smt.root = root
}

func (smt *SparseMerkleTree) depth() int {
    return smt.keySize() * 8
}

func (smt *SparseMerkleTree) keySize() int {
    return smt.hasher.Size()
}

func (smt *SparseMerkleTree) defaultNode(height int) []byte {
    return defaultNodes(smt.hasher)[height]
}

func (smt *SparseMerkleTree) digest(data []byte) []byte {
    smt.hasher.Write(data)
    sum := smt.hasher.Sum(nil)
    smt.hasher.Reset()
    return sum
}

func (smt *SparseMerkleTree) digestNode(data []byte) []byte {
    return smt.digest(append([]byte{nodePrefix}, data...))
}

func (smt *SparseMerkleTree) digestLeaf(data []byte) []byte {
    return smt.digest(append([]byte{leafPrefix}, data...))
}

// Get gets a key from the tree.
func (smt *SparseMerkleTree) Get(key []byte) ([]byte, error) {
    value, err := smt.GetForRoot(key, smt.Root())
    return value, err
}

// GetForRoot gets a key from the tree at a specific root.
func (smt *SparseMerkleTree) GetForRoot(key []byte, root []byte) ([]byte, error) {
    path := smt.digest(key)
    currentHash := root
    for i := 0; i < smt.depth(); i++ {
        currentValue, err := smt.ms.Get(currentHash)
        if err != nil {
            return nil, err
        }
        if hasBit(path, i) == right {
            currentHash = currentValue[smt.keySize():]
        } else {
            currentHash = currentValue[:smt.keySize()]
        }
    }

    value, err := smt.ms.Get(currentHash)
    if err != nil {
        return nil, err
    }

    return value, nil
}

// Update sets a new value for a key in the tree, returns the new root, and sets the new current root of the tree.
func (smt *SparseMerkleTree) Update(key []byte, value []byte) ([]byte, error) {
    newRoot, err := smt.UpdateForRoot(key, value, smt.Root())
    if err == nil {
        smt.SetRoot(newRoot)
    }
    return newRoot, err
}

// UpdateForRoot sets a new value for a key in the tree at a specific root, and returns the new root.
func (smt *SparseMerkleTree) UpdateForRoot(key []byte, value []byte, root []byte) ([]byte, error) {
    path := smt.digest(key)
    sideNodes, err := smt.sideNodesForRoot(path, root)
    if err != nil {
        return nil, err
    }

    newRoot, err := smt.updateWithSideNodes(path, value, sideNodes)
    return newRoot, err
}

func (smt *SparseMerkleTree) updateWithSideNodes(path []byte, value []byte, sideNodes [][]byte) ([]byte, error) {
    currentHash := smt.digestLeaf(value)
    smt.ms.Put(currentHash, value)
    currentValue := currentHash

    for i := smt.depth() - 1; i >= 0; i-- {
        sideNode := make([]byte, smt.keySize())
        copy(sideNode, sideNodes[i])
        if hasBit(path, i) == right {
            currentValue = append(sideNode, currentValue...)
        } else {
            currentValue = append(currentValue, sideNode...)
        }
        currentHash = smt.digestNode(currentValue)
        err := smt.ms.Put(currentHash, currentValue)
        if err != nil {
            return nil, err
        }
        currentValue = currentHash
    }

    return currentHash, nil
}

func (smt *SparseMerkleTree) sideNodesForRoot(path []byte, root []byte) ([][]byte, error) {
    currentValue, err := smt.ms.Get(root)
    if err != nil {
        return nil, err
    }

    sideNodes := make([][]byte, smt.depth())
    for i := 0; i < smt.depth(); i++ {
        if hasBit(path, i) == right {
            sideNodes[i] = currentValue[:smt.keySize()]
            currentValue, err = smt.ms.Get(currentValue[smt.keySize():])
            if err != nil {
                return nil, err
            }
        } else {
            sideNodes[i] = currentValue[smt.keySize():]
            currentValue, err = smt.ms.Get(currentValue[:smt.keySize()])
            if err != nil {
                return nil, err
            }
        }
    }

    return sideNodes, err
}

// Prove generates a Merkle proof for a key.
func (smt *SparseMerkleTree) Prove(key []byte) ([][]byte, error) {
    proof, err := smt.ProveForRoot(key, smt.Root())
    return proof, err
}

// ProveForRoot generates a Merkle proof for a key, at a specific root.
func (smt *SparseMerkleTree) ProveForRoot(key []byte, root []byte) ([][]byte, error) {
    sideNodes, err := smt.sideNodesForRoot(smt.digest(key), root)
    return sideNodes, err
}

// ProveCompact generates a compacted Merkle proof for a key.
func (smt *SparseMerkleTree) ProveCompact(key []byte) ([][]byte, error) {
    proof, err := smt.Prove(key)
    if err != nil {
        return nil, err
    }
    compactedProof, err := CompactProof(proof, smt.hasher)
    return compactedProof, err
}

// ProveCompactForRoot generates a compacted Merkle proof for a key, at a specific root.
func (smt *SparseMerkleTree) ProveCompactForRoot(key []byte, root []byte) ([][]byte, error) {
    proof, err := smt.ProveForRoot(key, root)
    if err != nil {
        return nil, err
    }
    compactedProof, err := CompactProof(proof, smt.hasher)
    return compactedProof, err
}
