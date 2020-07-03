// Package smt implements a Sparse Merkle tree.
package smt

import (
	"hash"
	"bytes"
)

const left = 0
const right = 1

var defaultValue = []byte{}

// SparseMerkleTree is a Sparse Merkle tree.
type SparseMerkleTree struct {
	th   treeHasher
	ms   MapStore
	root []byte
}

// NewSparseMerkleTree creates a new Sparse Merkle tree on an empty MapStore.
func NewSparseMerkleTree(ms MapStore, hasher hash.Hash) *SparseMerkleTree {
	smt := SparseMerkleTree{
		th: *newTreeHasher(hasher),
		ms: ms,
	}

	smt.SetRoot(smt.th.placeholder())

	return &smt
}

// ImportSparseMerkleTree imports a Sparse Merkle tree from a non-empty MapStore.
func ImportSparseMerkleTree(ms MapStore, hasher hash.Hash, root []byte) *SparseMerkleTree {
	smt := SparseMerkleTree{
		th:   *newTreeHasher(hasher),
		ms:   ms,
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
	return smt.th.pathSize() * 8
}

// Get gets a key from the tree.
func (smt *SparseMerkleTree) Get(key []byte) ([]byte, error) {
	value, err := smt.GetForRoot(key, smt.Root())
	return value, err
}

// GetForRoot gets a key from the tree at a specific root.
func (smt *SparseMerkleTree) GetForRoot(key []byte, root []byte) ([]byte, error) {
	path := smt.th.path(key)
	currentHash := root
	for i := 0; i < smt.depth(); i++ {
		currentValue, err := smt.ms.Get(currentHash)
		if err != nil {
			return nil, err
		}
		if hasBit(path, i) == right {
			currentHash = currentValue[smt.th.pathSize():]
		} else {
			currentHash = currentValue[:smt.th.pathSize()]
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
	path := smt.th.path(key)
	sideNodes, err := smt.sideNodesForRoot(path, root)
	if err != nil {
		return nil, err
	}

	newRoot, err := smt.updateWithSideNodes(path, value, sideNodes)
	return newRoot, err
}

func (smt *SparseMerkleTree) updateWithSideNodes(path []byte, value []byte, sideNodes [][]byte) ([]byte, error) {
	currentHash := smt.th.digestLeaf(path, value)
	smt.ms.Put(currentHash, value)
	currentValue := currentHash

	for i := smt.depth() - 1; i >= 0; i-- {
		sideNode := make([]byte, smt.th.pathSize())
		copy(sideNode, sideNodes[i])
		if hasBit(path, i) == right {
			currentHash = smt.th.digestNode(sideNode, currentValue)
			currentValue = append(sideNode, currentValue...)
		} else {
			currentHash = smt.th.digestNode(currentValue, sideNode)
			currentValue = append(currentValue, sideNode...)
		}
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
		if bytes.Compare(currentValue, smt.th.placeholder()) == 0 || isLeaf(currentValue) {
			// if we hit the placeholder value or a leaf, stop and return all the sidenodes so far
			return sideNodes, err
		}

		if hasBit(path, i) == right {
			leftNode, rightNode := smt.th.parseNode(currentValue)
			sideNodes[i] = leftNode
			currentValue, err = smt.ms.Get(rightNode)
			if err != nil {
				return nil, err
			}
		} else {
			leftNode, rightNode := smt.th.parseNode(currentValue)
			sideNodes[i] = rightNode
			currentValue, err = smt.ms.Get(leftNode)
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
	sideNodes, err := smt.sideNodesForRoot(smt.th.path(key), root)
	return sideNodes, err
}

/*// ProveCompact generates a compacted Merkle proof for a key.
func (smt *SparseMerkleTree) ProveCompact(key []byte) ([][]byte, error) {
	proof, err := smt.Prove(key)
	if err != nil {
		return nil, err
	}
	compactedProof, err := CompactProof(proof, smt.th.hasher)
	return compactedProof, err
}

// ProveCompactForRoot generates a compacted Merkle proof for a key, at a specific root.
func (smt *SparseMerkleTree) ProveCompactForRoot(key []byte, root []byte) ([][]byte, error) {
	proof, err := smt.ProveForRoot(key, root)
	if err != nil {
		return nil, err
	}
	compactedProof, err := CompactProof(proof, smt.th.hasher)
	return compactedProof, err
}*/
