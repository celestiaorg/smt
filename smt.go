// Package smt implements a Sparse Merkle tree.
package smt

import (
	"bytes"
	"hash"
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
	sideNodes, oldLeaf, actualPath, err := smt.sideNodesForRoot(path, root)
	if err != nil {
		return nil, err
	}

	newRoot, err := smt.updateWithSideNodes(path, value, sideNodes, oldLeaf, actualPath)
	return newRoot, err
}

func (smt *SparseMerkleTree) updateWithSideNodes(path []byte, value []byte, sideNodes [][]byte, oldLeaf []byte, actualPath []byte) ([]byte, error) {
	var currentHash []byte
	if bytes.Equal(value, defaultValue) {
		// If the input value is the default value, then explicitly set the leaf hash to a placeholder.
		currentHash = smt.th.placeholder()
	} else {
		currentHash := smt.th.digestLeaf(path, value)
		smt.ms.Put(currentHash, value)
	}
	currentValue := currentHash

	// If the leaf node that sibling nodes lead to has a different actual path than the leaf node being updated, we need to create an intermediate node with this leaf node and the new leaf node as children.
	commonPrefixCount := countCommonPrefix(path, actualPath) // Get the number of bits that the paths of the two leaf nodes share in common as a prefix.
	if commonPrefixCount != smt.depth() {
		if bytes.Compare(path, actualPath) > 0 {
			currentHash = smt.th.digestNode(oldLeaf, currentValue)
			currentValue = append(oldLeaf, currentValue...)
		} else {
			currentHash = smt.th.digestNode(currentValue, oldLeaf)
			currentValue = append(currentValue, oldLeaf...)
		}

		err := smt.ms.Put(currentHash, currentValue)
		if err != nil {
			return nil, err
		}

		currentValue = currentHash
	}

	for i := smt.depth() - 1; i >= 0; i-- {
		sideNode := make([]byte, smt.th.pathSize())

		if sideNodes[i] == nil {
			if commonPrefixCount != smt.depth() && commonPrefixCount <= i {
				// If there are no sidenodes at this height, and but the number of bits that the paths of the two leaf nodes share in common is greater than this height, then we need to build up the tree to this height with placeholder values at siblings.
				copy(sideNode, smt.th.placeholder())
			} else {
				continue
			}
		} else {
			copy(sideNode, sideNodes[i])
		}

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

// Get all the sibling nodes (sidenodes) for a given path from a given root.
// Returns an array of sibling nodes, the leaf hash found at that path and the actual path of that leaf according to its value.
func (smt *SparseMerkleTree) sideNodesForRoot(path []byte, root []byte) ([][]byte, []byte, []byte, error) {
	sideNodes := make([][]byte, smt.depth())

	if bytes.Equal(root, smt.th.placeholder()) {
		// If the root is a placeholder, there are no sidenodes to return.
		// Let the "actual path" be the input path.
		return sideNodes, root, path, nil
	}

	currentValue, err := smt.ms.Get(root)
	if err != nil {
		return nil, nil, nil, err
	} else if smt.th.isLeaf(currentValue) {
		// If the root is a leaf, there are also no sidenodes to return.
		actualPath, _ := smt.th.parseLeaf(currentValue)
		return sideNodes, root, actualPath, nil
	}

	var leafHash []byte
	for i := 0; i < smt.depth(); i++ {
		leftNode, rightNode := smt.th.parseNode(currentValue)

		// Get sidenode depending on whether the path bit is on or off.
		if hasBit(path, i) == right {
			sideNodes[i] = leftNode
			leafHash = rightNode
		} else {
			sideNodes[i] = rightNode
			leafHash = leftNode
		}

		if bytes.Equal(leftNode, smt.th.placeholder()) {
			// If the node is a placeholder, we've reached the end.
			return sideNodes, leafHash, path, nil
		}

		currentValue, err = smt.ms.Get(leftNode)
		if err != nil {
			return nil, nil, nil, err
		} else if smt.th.isLeaf(currentValue) {
			// If the node is a leaf, we've reached the end.
			break
		}
	}

	actualPath, _ := smt.th.parseLeaf(currentValue) // Get the actual path of the leaf according to its value.
	return sideNodes, leafHash, actualPath, err
}

// Prove generates a Merkle proof for a key.
func (smt *SparseMerkleTree) Prove(key []byte) ([][]byte, error) {
	proof, err := smt.ProveForRoot(key, smt.Root())
	return proof, err
}

// ProveForRoot generates a Merkle proof for a key, at a specific root.
func (smt *SparseMerkleTree) ProveForRoot(key []byte, root []byte) ([][]byte, error) {
	sideNodes, _, _, err := smt.sideNodesForRoot(smt.th.path(key), root)
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
