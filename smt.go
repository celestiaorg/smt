// Package smt implements a Sparse Merkle tree.
package smt

import (
	"bytes"
	"errors"
	"hash"
)

const (
	right = 1
)

var defaultValue = []byte{}

var errKeyAlreadyEmpty = errors.New("key already empty")

// SparseMerkleTree is a Sparse Merkle tree.
type SparseMerkleTree struct {
	th            treeHasher
	nodes, values MapStore
	root          []byte
}

// NewSparseMerkleTree creates a new Sparse Merkle tree on an empty MapStore.
func NewSparseMerkleTree(nodes, values MapStore, hasher hash.Hash, options ...Option) *SparseMerkleTree {
	smt := SparseMerkleTree{
		th:     *newTreeHasher(hasher),
		nodes:  nodes,
		values: values,
	}

	for _, option := range options {
		option(&smt)
	}

	smt.SetRoot(smt.th.placeholder())

	return &smt
}

// ImportSparseMerkleTree imports a Sparse Merkle tree from a non-empty MapStore.
func ImportSparseMerkleTree(nodes, values MapStore, hasher hash.Hash, root []byte) *SparseMerkleTree {
	smt := SparseMerkleTree{
		th:     *newTreeHasher(hasher),
		nodes:  nodes,
		values: values,
		root:   root,
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
	return smt.values.GetKeySize() * 8
}

// Get gets the value of a key from the tree.
func (smt *SparseMerkleTree) Get(key []byte) ([]byte, error) {
	// Get tree's root
	root := smt.Root()

	if bytes.Equal(root, smt.th.placeholder()) {
		// The tree is empty, return the default value.
		return defaultValue, nil
	}

	value, err := smt.values.Get(key)

	if err != nil {
		var invalidKeyError *InvalidKeyError

		if errors.As(err, &invalidKeyError) {
			// If key isn't found, return default value
			return defaultValue, nil
		}
		// Otherwise, percolate up any other error
		return nil, err
	}
	return value, nil
}

// Has returns true if the value at the given key is non-default, false
// otherwise.
func (smt *SparseMerkleTree) Has(key []byte) (bool, error) {
	val, err := smt.Get(key)
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
	sideNodes, pathNodes, oldLeafData, _, err := smt.sideNodesForRoot(key, root, false)
	if err != nil {
		return nil, err
	}

	var newRoot []byte
	if bytes.Equal(value, defaultValue) {
		// Delete operation.
		newRoot, err = smt.deleteWithSideNodes(key, sideNodes, pathNodes, oldLeafData)
		if errors.Is(err, errKeyAlreadyEmpty) {
			// This key is already empty; return the old root.
			return root, nil
		}
		if err := smt.values.Delete(key); err != nil {
			return nil, err
		}
	} else {
		// Insert or update operation.
		newRoot, err = smt.updateWithSideNodes(key, value, sideNodes, pathNodes, oldLeafData)
	}
	return newRoot, err
}

// DeleteForRoot deletes a value from tree at a specific root. It returns the new root of the tree.
func (smt *SparseMerkleTree) DeleteForRoot(key, root []byte) ([]byte, error) {
	return smt.UpdateForRoot(key, defaultValue, root)
}

func (smt *SparseMerkleTree) deleteWithSideNodes(key []byte, sideNodes [][]byte, pathNodes [][]byte, oldLeafData []byte) ([]byte, error) {
	if bytes.Equal(pathNodes[0], smt.th.placeholder()) {
		// This key is already empty as it is a placeholder; return an error.
		return nil, errKeyAlreadyEmpty
	}
	actualKey, _ := smt.th.parseLeaf(oldLeafData, smt.values.GetKeySize())
	if !bytes.Equal(key, actualKey) {
		// This key is already empty as a different key was found its place; return an error.
		return nil, errKeyAlreadyEmpty
	}
	// All nodes above the deleted leaf are now orphaned
	for _, node := range pathNodes {
		if err := smt.nodes.Delete(node); err != nil {
			return nil, err
		}
	}

	var currentHash, currentData []byte
	nonPlaceholderReached := false
	for i, sideNode := range sideNodes {
		if currentData == nil {
			sideNodeValue, err := smt.nodes.Get(sideNode)
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
			// We found another placeholder sibling node, keep going up the
			// tree until we find the first sibling that is not a placeholder.
			continue
		} else if !nonPlaceholderReached {
			// We found the first sibling node that is not a placeholder, it is
			// time to insert our leaf sibling node here.
			nonPlaceholderReached = true
		}

		if getBitAtFromMSB(key, len(sideNodes)-1-i) == right {
			currentHash, currentData = smt.th.digestNode(sideNode, currentData)
		} else {
			currentHash, currentData = smt.th.digestNode(currentData, sideNode)
		}
		if err := smt.nodes.Set(currentHash, currentData); err != nil {
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

func (smt *SparseMerkleTree) updateWithSideNodes(path []byte, value []byte, sideNodes [][]byte, pathNodes [][]byte, oldLeafData []byte) ([]byte, error) {
	valueHash := smt.th.digest(value)
	currentHash, currentData := smt.th.digestLeaf(path, valueHash)
	if err := smt.nodes.Set(currentHash, currentData); err != nil {
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
	var oldValueHash []byte
	if bytes.Equal(pathNodes[0], smt.th.placeholder()) {
		commonPrefixCount = smt.depth()
	} else {
		var actualPath []byte
		actualPath, oldValueHash = smt.th.parseLeaf(oldLeafData, smt.values.GetKeySize())
		commonPrefixCount = countCommonPrefix(path, actualPath)
	}
	if commonPrefixCount != smt.depth() {
		if getBitAtFromMSB(path, commonPrefixCount) == right {
			currentHash, currentData = smt.th.digestNode(pathNodes[0], currentData)
		} else {
			currentHash, currentData = smt.th.digestNode(currentData, pathNodes[0])
		}

		err := smt.nodes.Set(currentHash, currentData)
		if err != nil {
			return nil, err
		}

		currentData = currentHash
	} else if oldValueHash != nil {
		// Short-circuit if the same value is being set
		if bytes.Equal(oldValueHash, valueHash) {
			return smt.root, nil
		}
		// If an old leaf exists, remove it
		if err := smt.nodes.Delete(pathNodes[0]); err != nil {
			return nil, err
		}
		if err := smt.values.Delete(path); err != nil {
			return nil, err
		}
	}
	// All remaining path nodes are orphaned
	for i := 1; i < len(pathNodes); i++ {
		if err := smt.nodes.Delete(pathNodes[i]); err != nil {
			return nil, err
		}
	}

	// The offset from the bottom of the tree to the start of the side nodes.
	// Note: i-offsetOfSideNodes is the index into sideNodes[]
	offsetOfSideNodes := smt.depth() - len(sideNodes)

	for i := 0; i < smt.depth(); i++ {
		var sideNode []byte

		if i-offsetOfSideNodes < 0 || sideNodes[i-offsetOfSideNodes] == nil {
			if commonPrefixCount != smt.depth() && commonPrefixCount > smt.depth()-1-i {
				// If there are no sidenodes at this height, but the number of
				// bits that the paths of the two leaf nodes share in common is
				// greater than this depth, then we need to build up the tree
				// to this depth with placeholder values at siblings.
				sideNode = smt.th.placeholder()
			} else {
				continue
			}
		} else {
			sideNode = sideNodes[i-offsetOfSideNodes]
		}

		if getBitAtFromMSB(path, smt.depth()-1-i) == right {
			currentHash, currentData = smt.th.digestNode(sideNode, currentData)
		} else {
			currentHash, currentData = smt.th.digestNode(currentData, sideNode)
		}
		err := smt.nodes.Set(currentHash, currentData)
		if err != nil {
			return nil, err
		}
		currentData = currentHash
	}
	if err := smt.values.Set(path, value); err != nil {
		return nil, err
	}

	return currentHash, nil
}

// Get all the sibling nodes (sidenodes) for a given path from a given root.
// Returns an array of sibling nodes, the leaf hash found at that path, the
// leaf data, and the sibling data.
//
// If the leaf is a placeholder, the leaf data is nil.
func (smt *SparseMerkleTree) sideNodesForRoot(path []byte, root []byte, getSiblingData bool) ([][]byte, [][]byte, []byte, []byte, error) {
	if len(path) != smt.values.GetKeySize() {
		return nil, nil, nil, nil, ErrWrongKeySize
	}
	// Side nodes for the path. Nodes are inserted in reverse order, then the
	// slice is reversed at the end.
	sideNodes := make([][]byte, 0, smt.depth())
	pathNodes := make([][]byte, 0, smt.depth()+1)
	pathNodes = append(pathNodes, root)

	if bytes.Equal(root, smt.th.placeholder()) {
		// If the root is a placeholder, there are no sidenodes to return.
		// Let the "actual path" be the input path.
		return sideNodes, pathNodes, nil, nil, nil
	}

	currentData, err := smt.nodes.Get(root)
	if err != nil {
		return nil, nil, nil, nil, err
	} else if smt.th.isLeaf(currentData) {
		// If the root is a leaf, there are also no sidenodes to return.
		return sideNodes, pathNodes, currentData, nil, nil
	}

	var nodeHash []byte
	var sideNode []byte
	var siblingData []byte
	for i := 0; i < smt.depth(); i++ {
		leftNode, rightNode := smt.th.parseNode(currentData)

		// Get sidenode depending on whether the path bit is on or off.
		if getBitAtFromMSB(path, i) == right {
			sideNode = leftNode
			nodeHash = rightNode
		} else {
			sideNode = rightNode
			nodeHash = leftNode
		}
		sideNodes = append(sideNodes, sideNode)
		pathNodes = append(pathNodes, nodeHash)

		if bytes.Equal(nodeHash, smt.th.placeholder()) {
			// If the node is a placeholder, we've reached the end.
			currentData = nil
			break
		}

		currentData, err = smt.nodes.Get(nodeHash)
		if err != nil {
			return nil, nil, nil, nil, err
		} else if smt.th.isLeaf(currentData) {
			// If the node is a leaf, we've reached the end.
			break
		}
	}

	if getSiblingData {
		siblingData, err = smt.nodes.Get(sideNode)
		if err != nil {
			return nil, nil, nil, nil, err
		}
	}
	return reverseByteSlices(sideNodes), reverseByteSlices(pathNodes), currentData, siblingData, nil
}

// Prove generates a Merkle proof for a key against the current root.
//
// This proof can be used for read-only applications, but should not be used if
// the leaf may be updated (e.g. in a state transition fraud proof). For
// updatable proofs, see ProveUpdatable.
func (smt *SparseMerkleTree) Prove(key []byte) (SparseMerkleProof, error) {
	proof, err := smt.ProveForRoot(key, smt.Root())
	return proof, err
}

// ProveForRoot generates a Merkle proof for a key, against a specific node.
// This is primarily useful for generating Merkle proofs for subtrees.
//
// This proof can be used for read-only applications, but should not be used if
// the leaf may be updated (e.g. in a state transition fraud proof). For
// updatable proofs, see ProveUpdatableForRoot.
func (smt *SparseMerkleTree) ProveForRoot(key []byte, root []byte) (SparseMerkleProof, error) {
	return smt.doProveForRoot(key, root, false)
}

// ProveUpdatable generates an updatable Merkle proof for a key against the current root.
func (smt *SparseMerkleTree) ProveUpdatable(key []byte) (SparseMerkleProof, error) {
	proof, err := smt.ProveUpdatableForRoot(key, smt.Root())
	return proof, err
}

// ProveUpdatableForRoot generates an updatable Merkle proof for a key, against a specific node.
// This is primarily useful for generating Merkle proofs for subtrees.
func (smt *SparseMerkleTree) ProveUpdatableForRoot(key []byte, root []byte) (SparseMerkleProof, error) {
	return smt.doProveForRoot(key, root, true)
}

func (smt *SparseMerkleTree) doProveForRoot(key []byte, root []byte, isUpdatable bool) (SparseMerkleProof, error) {
	sideNodes, pathNodes, leafData, siblingData, err := smt.sideNodesForRoot(key, root, isUpdatable)
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
	if !bytes.Equal(pathNodes[0], smt.th.placeholder()) {
		actualKey, _ := smt.th.parseLeaf(leafData, smt.values.GetKeySize())
		if !bytes.Equal(actualKey, key) {
			// This is a non-membership proof that involves showing a different leaf.
			// Add the leaf data to the proof.
			nonMembershipLeafData = leafData
		}
	}

	proof := SparseMerkleProof{
		SideNodes:             nonEmptySideNodes,
		NonMembershipLeafData: nonMembershipLeafData,
		SiblingData:           siblingData,
	}

	return proof, err
}

// ProveCompact generates a compacted Merkle proof for a key against the current root.
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
	compactedProof, err := CompactProof(proof, smt.th.hasher, smt.values.GetKeySize())
	return compactedProof, err
}
