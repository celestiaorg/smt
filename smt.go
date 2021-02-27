// Package smt implements a Sparse Merkle tree.
package smt

import (
	"bytes"
	"hash"
)

const (
	right = 1
)

var defaultValue = []byte{}

type keyAlreadyEmptyError struct{}

func (e *keyAlreadyEmptyError) Error() string {
	return "key already empty"
}

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
	if bytes.Equal(root, smt.th.placeholder()) {
		// The tree is empty, return the default value.
		return defaultValue, nil
	}

	path := smt.th.path(key)
	currentHash := root
	for i := 0; i < smt.depth(); i++ {
		currentData, err := smt.ms.Get(currentHash)
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
			value, err := smt.ms.Get(valueHash)
			if err != nil {
				return nil, err
			}
			return value, nil
		}

		leftNode, rightNode := smt.th.parseNode(currentData)
		if hasBit(path, i) == right {
			currentHash = rightNode
		} else {
			currentHash = leftNode
		}

		if bytes.Equal(currentHash, smt.th.placeholder()) {
			// We've hit a placeholder value; this is the end.
			return defaultValue, nil
		}
	}

	// The following lines of code should only be reached if the path is 256
	// nodes high, which should be very unlikely if the underlying hash function
	// is collision-resistance.
	currentData, err := smt.ms.Get(currentHash)
	if err != nil {
		return nil, err
	}
	_, valueHash := smt.th.parseLeaf(currentData)
	value, err := smt.ms.Get(valueHash)
	if err != nil {
		return nil, err
	}
	return value, nil
}

// Has returns true if tree cointains given key, false otherwise.
func (smt *SparseMerkleTree) Has(key []byte) (bool, error) {
	val, err := smt.Get(key)
	return !bytes.Equal(defaultValue, val), err
}

// HasForRoot returns true if tree cointains given key at a specific root, false otherwise.
func (smt *SparseMerkleTree) HasForRoot(key, root []byte) (bool, error) {
	val, err := smt.GetForRoot(key, root)
	return !bytes.Equal(defaultValue, val), err
}

// Update sets a new value for a key in the tree, and sets and returns the new root of the tree.
func (smt *SparseMerkleTree) Update(key []byte, value []byte) ([]byte, error) {
	newRoot, err := smt.UpdateForRoot(key, value, smt.Root())
	if err != nil {
		return nil, err
	}
	smt.SetRoot(newRoot)
	return newRoot, nil
}

// Delete deletes a value from tree. It returns the new root of the tree.
func (smt *SparseMerkleTree) Delete(key []byte) ([]byte, error) {
	return smt.Update(key, defaultValue)
}

// UpdateForRoot sets a new value for a key in the tree at a specific root, and returns the new root.
func (smt *SparseMerkleTree) UpdateForRoot(key []byte, value []byte, root []byte) ([]byte, error) {
	path := smt.th.path(key)
	sideNodes, oldLeafHash, oldLeafData, err := smt.sideNodesForRoot(path, root)
	if err != nil {
		return nil, err
	}

	var newRoot []byte
	if bytes.Equal(value, defaultValue) {
		// Delete operation.
		newRoot, err = smt.deleteWithSideNodes(path, sideNodes, oldLeafHash, oldLeafData)
		if _, ok := err.(*keyAlreadyEmptyError); ok {
			// This key is already empty; return the old root.
			return root, nil
		}
	} else {
		// Insert or update operation.
		newRoot, err = smt.updateWithSideNodes(path, value, sideNodes, oldLeafHash, oldLeafData)
	}
	return newRoot, err
}

// Delete deletes a value from tree at a specific root. It returns the new root of the tree.
func (smt *SparseMerkleTree) DeleteForRoot(key, root []byte) ([]byte, error) {
	return smt.UpdateForRoot(key, defaultValue, root)
}

func (smt *SparseMerkleTree) deleteWithSideNodes(path []byte, sideNodes [][]byte, oldLeafHash []byte, oldLeafData []byte) ([]byte, error) {
	if bytes.Equal(oldLeafHash, smt.th.placeholder()) {
		// This key is already empty as it is a placeholder; return an error.
		return nil, &keyAlreadyEmptyError{}
	} else if actualPath, _ := smt.th.parseLeaf(oldLeafData); !bytes.Equal(path, actualPath) {
		// This key is already empty as a different key was found its place; return an error.
		return nil, &keyAlreadyEmptyError{}
	}

	var currentHash, currentData []byte
	nonPlaceholderReached := false
	for i := smt.depth() - 1; i >= 0; i-- {
		if sideNodes[i] == nil {
			continue
		}

		sideNode := make([]byte, smt.th.pathSize())
		copy(sideNode, sideNodes[i])

		if currentData == nil {
			sideNodeValue, err := smt.ms.Get(sideNode)
			if err != nil {
				return nil, err
			}

			if smt.th.isLeaf(sideNodeValue) {
				// This is the leaf sibling that needs to be bubbled up the tree.
				currentHash = sideNode
				currentData = sideNode
				continue
			} else {
				// This is the node sibling that needs to be left in its place.
				currentData = smt.th.placeholder()
				nonPlaceholderReached = true
			}
		}

		if !nonPlaceholderReached && bytes.Equal(sideNode, smt.th.placeholder()) {
			// We found another placeholder sibling node, keep going down the
			// tree until we find the first sibling that is not a placeholder.
			continue
		} else if !nonPlaceholderReached {
			// We found the first sibling node that is not a placeholder, it is
			// time to insert our leaf sibling node here.
			nonPlaceholderReached = true
		}

		if hasBit(path, i) == right {
			currentHash, currentData = smt.th.digestNode(sideNode, currentData)
		} else {
			currentHash, currentData = smt.th.digestNode(currentData, sideNode)
		}
		err := smt.ms.Set(currentHash, currentData)
		if err != nil {
			return nil, err
		}
		currentData = currentHash
	}

	if currentHash == nil {
		// The tree is empty; return placeholder value as root.
		currentHash = smt.th.placeholder()
	}
	return currentHash, nil
}

func (smt *SparseMerkleTree) updateWithSideNodes(path []byte, value []byte, sideNodes [][]byte, oldLeafHash []byte, oldLeafData []byte) ([]byte, error) {
	valueHash := smt.th.digest(value)
	if err := smt.ms.Set(valueHash, value); err != nil {
		return nil, err
	}

	currentHash, currentData := smt.th.digestLeaf(path, valueHash)
	if err := smt.ms.Set(currentHash, currentData); err != nil {
		return nil, err
	}
	currentData = currentHash

	// If the leaf node that sibling nodes lead to has a different actual path
	// than the leaf node being updated, we need to create an intermediate node
	// with this leaf node and the new leaf node as children.
	//
	// First, get the number of bits that the paths of the two leaf nodes share
	// in common as a prefix.
	var commonPrefixCount int
	if bytes.Equal(oldLeafHash, smt.th.placeholder()) {
		commonPrefixCount = smt.depth()
	} else {
		actualPath, _ := smt.th.parseLeaf(oldLeafData)
		commonPrefixCount = countCommonPrefix(path, actualPath)
	}
	if commonPrefixCount != smt.depth() {
		if hasBit(path, commonPrefixCount) == right {
			currentHash, currentData = smt.th.digestNode(oldLeafHash, currentData)
		} else {
			currentHash, currentData = smt.th.digestNode(currentData, oldLeafHash)
		}

		err := smt.ms.Set(currentHash, currentData)
		if err != nil {
			return nil, err
		}

		currentData = currentHash
	}

	for i := smt.depth() - 1; i >= 0; i-- {
		sideNode := make([]byte, smt.th.pathSize())

		if sideNodes[i] == nil {
			if commonPrefixCount != smt.depth() && commonPrefixCount > i {
				// If there are no sidenodes at this height, but the number of
				// bits that the paths of the two leaf nodes share in common is
				// greater than this height, then we need to build up the tree
				// to this height with placeholder values at siblings.
				copy(sideNode, smt.th.placeholder())
			} else {
				continue
			}
		} else {
			copy(sideNode, sideNodes[i])
		}

		if hasBit(path, i) == right {
			currentHash, currentData = smt.th.digestNode(sideNode, currentData)
		} else {
			currentHash, currentData = smt.th.digestNode(currentData, sideNode)
		}
		err := smt.ms.Set(currentHash, currentData)
		if err != nil {
			return nil, err
		}
		currentData = currentHash
	}

	return currentHash, nil
}

// Get all the sibling nodes (sidenodes) for a given path from a given root.
// Returns an array of sibling nodes, the leaf hash found at that path and the
// leaf data. If the leaf is a placeholder, the leaf data is nil.
func (smt *SparseMerkleTree) sideNodesForRoot(path []byte, root []byte) ([][]byte, []byte, []byte, error) {
	sideNodes := make([][]byte, smt.depth())

	if bytes.Equal(root, smt.th.placeholder()) {
		// If the root is a placeholder, there are no sidenodes to return.
		// Let the "actual path" be the input path.
		return sideNodes, smt.th.placeholder(), nil, nil
	}

	currentData, err := smt.ms.Get(root)
	if err != nil {
		return nil, nil, nil, err
	} else if smt.th.isLeaf(currentData) {
		// If the root is a leaf, there are also no sidenodes to return.
		return sideNodes, root, currentData, nil
	}

	var nodeHash []byte
	for i := 0; i < smt.depth(); i++ {
		leftNode, rightNode := smt.th.parseNode(currentData)

		// Get sidenode depending on whether the path bit is on or off.
		if hasBit(path, i) == right {
			sideNodes[i] = leftNode
			nodeHash = rightNode
		} else {
			sideNodes[i] = rightNode
			nodeHash = leftNode
		}

		if bytes.Equal(nodeHash, smt.th.placeholder()) {
			// If the node is a placeholder, we've reached the end.
			return sideNodes, nodeHash, nil, nil
		}

		currentData, err = smt.ms.Get(nodeHash)
		if err != nil {
			return nil, nil, nil, err
		} else if smt.th.isLeaf(currentData) {
			// If the node is a leaf, we've reached the end.
			break
		}
	}

	return sideNodes, nodeHash, currentData, err
}

// Prove generates a Merkle proof for a key.
func (smt *SparseMerkleTree) Prove(key []byte) (SparseMerkleProof, error) {
	proof, err := smt.ProveForRoot(key, smt.Root())
	return proof, err
}

// ProveForRoot generates a Merkle proof for a key, at a specific root.
func (smt *SparseMerkleTree) ProveForRoot(key []byte, root []byte) (SparseMerkleProof, error) {
	path := smt.th.path(key)
	sideNodes, leafHash, leafData, err := smt.sideNodesForRoot(path, root)
	if err != nil {
		return SparseMerkleProof{}, err
	}

	var nonEmptySideNodes [][]byte
	for _, v := range sideNodes {
		if v != nil {
			nonEmptySideNodes = append(nonEmptySideNodes, v)
		}
	}

	// Deal with non-membership proofs. If the leaf hash is the placeholder
	// value, we do not need to add anything else to the proof.
	var nonMembershipLeafData []byte
	if !bytes.Equal(leafHash, smt.th.placeholder()) {
		// This is a non-membership proof that involves showing a different leaf.
		// Add the leaf data to the proof.
		nonMembershipLeafData = leafData
	}

	proof := SparseMerkleProof{
		SideNodes:             nonEmptySideNodes,
		NonMembershipLeafData: nonMembershipLeafData,
	}

	return proof, err
}

// ProveCompact generates a compacted Merkle proof for a key.
func (smt *SparseMerkleTree) ProveCompact(key []byte) (SparseCompactMerkleProof, error) {
	proof, err := smt.ProveCompactForRoot(key, smt.Root())
	return proof, err
}

// ProveCompactForRoot generates a compacted Merkle proof for a key, at a specific root.
func (smt *SparseMerkleTree) ProveCompactForRoot(key []byte, root []byte) (SparseCompactMerkleProof, error) {
	proof, err := smt.ProveForRoot(key, root)
	if err != nil {
		return SparseCompactMerkleProof{}, err
	}
	compactedProof, err := CompactProof(proof, smt.th.hasher)
	return compactedProof, err
}
