// Package smt implements a Sparse Merkle tree.
package smt

import (
	"bytes"
	"errors"
	"hash"
)

const (
	right = 1 // ASK(reviewer): Are we only dealing with binary trees?
)

var (
	// ASK(reviewer): rename to `emptySubtreeNode`?
	defaultValue = make([]byte, 0)

	// errors
	errKeyAlreadyEmpty = errors.New("key already empty")
)

type SparseMerkleTree struct {
	th            treeHasher
	nodes, values MapStore
	root          []byte
}

// `Creates a new Sparse Merkle tree on an empty MapStore
func NewSparseMerkleTree(nodes, values MapStore, hasher hash.Hash, options ...Option) *SparseMerkleTree {
	smt := SparseMerkleTree{
		th:     *newTreeHasher(hasher),
		nodes:  nodes,  // ASK(reviewer): there is no validation that this is empty. Should we check?
		values: values, // ASK(reviewer): there is no validation that this is empty. Should we check?
	}

	for _, option := range options {
		option(&smt)
	}

	smt.setRoot(smt.th.placeholder())

	return &smt
}

// `Imports a Sparse Merkle tree from a non-empty MapStore.
func ImportSparseMerkleTree(nodes, values MapStore, hasher hash.Hash, root []byte) *SparseMerkleTree {
	smt := SparseMerkleTree{
		th:     *newTreeHasher(hasher),
		nodes:  nodes,  // ASK(reviewer): No validation that this corresponds to the root provided
		values: values, // ASK(reviewer): No validation that this corresponds to the root provided
		root:   root,
	}
	return &smt
}

// Returns the root of the tree.
func (smt *SparseMerkleTree) Root() []byte {
	return smt.root
}

// Sets the root of the tree.
func (smt *SparseMerkleTree) setRoot(root []byte) {
	smt.root = root
}

// ASK(reviewer): Why is the depth of the tree the size of the hash in bits?
//                Per JMT, it should be depending on the `k-ary` of the tree and the size of the hash.
//                E.g. if we are using a 256 bit hasher, the MAX depth is logk(256)
func (smt *SparseMerkleTree) depth() int {
	return smt.th.pathSize() * 8
}

// Gets the value of a key from the tree.
func (smt *SparseMerkleTree) Get(key []byte) ([]byte, error) {
	// Get tree's root
	root := smt.Root()

	// If the tree is empty, return the default value
	if bytes.Equal(root, smt.th.placeholder()) {
		return defaultValue, nil
	}

	// Retrieve the value based on the path
	path := smt.th.path(key)
	value, err := smt.values.Get(path)
	if err == nil {
		return value, nil
	}

	// If key isn't found, return default value
	var invalidKeyError *InvalidKeyError
	if errors.As(err, &invalidKeyError) {
		return defaultValue, nil
	}

	// Otherwise percolate up any other error
	return nil, err
}

// Returns true if the value at the given key is non-default, false otherwise.
func (smt *SparseMerkleTree) Has(key []byte) (bool, error) {
	value, err := smt.Get(key)
	return !bytes.Equal(defaultValue, value), err
}

// Sets a new value for a key in the tree, and returns the new root of the tree.
func (smt *SparseMerkleTree) Update(key, value []byte) ([]byte, error) {
	newRoot, err := smt.updateForRoot(key, value, smt.Root())
	if err != nil {
		return nil, err
	}
	smt.setRoot(newRoot)
	return newRoot, nil
}

// Internal helper for `Update`
func (smt *SparseMerkleTree) updateForRoot(key, value, root []byte) ([]byte, error) {
	path := smt.th.path(key)
	sideNodes, pathNodes, oldLeafData, _, err := smt.sideNodesForRoot(path, root)
	if err != nil {
		return nil, err
	}

	var newRoot []byte
	if bytes.Equal(value, defaultValue) {
		// Delete operation.
		newRoot, err = smt.deleteWithSideNodes(path, sideNodes, pathNodes, oldLeafData)
		if errors.Is(err, errKeyAlreadyEmpty) {
			// This key is already empty; return the old root.
			return root, nil
		}
		if err := smt.values.Delete(path); err != nil {
			return nil, err
		}
	} else {
		// Insert or update operation.
		newRoot, err = smt.updateWithSideNodes(path, value, sideNodes, pathNodes, oldLeafData)
	}
	return newRoot, err
}

// Deletes the key-value mapping from the tree and returns the new root
func (smt *SparseMerkleTree) Delete(key []byte) ([]byte, error) {
	return smt.Update(key, defaultValue)
}

func (smt *SparseMerkleTree) deleteWithSideNodes(path []byte, sideNodes, pathNodes [][]byte, oldLeafData []byte) ([]byte, error) {
	// Checking if the first node of the path (i.e. the root) is a placeholder
	if bytes.Equal(pathNodes[0], smt.th.placeholder()) {
		return nil, errKeyAlreadyEmpty
	}

	oldPath, _ := smt.th.parseLeaf(oldLeafData)
	if !bytes.Equal(path, oldPath) {
		// The node path to the old leaf does not exist, which means the key is already empty
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
				currentData = sideNode // ASK(REVIEWER): Why are we settings hash and data to the same value?
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

		// Determine if `currentData` is currently a left or right child.
		// ASK(REVIEWER): Unclear how getting this specific bit determines the orientation of the tree
		if getBitAtFromMSB(path, len(sideNodes)-1-i) == right {
			currentHash, currentData = smt.th.digestNode(sideNode, currentData)
		} else {
			currentHash, currentData = smt.th.digestNode(currentData, sideNode)
		}
		if err := smt.nodes.Set(currentHash, currentData); err != nil {
			return nil, err
		}
		currentData = currentHash // ASK(REVIEWER): Unclear why we're doing this
	}

	if currentHash == nil {
		// The tree is empty; return placeholder value as root.
		currentHash = smt.th.placeholder()
	}
	return currentHash, nil
}

func (smt *SparseMerkleTree) updateWithSideNodes(path, value []byte, sideNodes, pathNodes [][]byte, oldLeafData []byte) ([]byte, error) {
	valueHash := smt.th.digest(value)
	currentHash, currentData := smt.th.digestLeaf(path, valueHash)
	if err := smt.nodes.Set(currentHash, currentData); err != nil {
		return nil, err
	}
	currentData = currentHash // ASK(REVIEWER): Again, trying to understand this logic

	// If the leaf node that sibling nodes lead to has a different actual path
	// than the leaf node being updated, we need to create an intermediate node
	// with this leaf node and the new leaf nodes as children.
	//
	// First, get the number of bits that the paths of the two leaf nodes share
	// in common as a prefix.
	var commonPrefixCount int
	var oldValueHash []byte
	if bytes.Equal(pathNodes[0], smt.th.placeholder()) {
		commonPrefixCount = smt.depth()
	} else {
		var actualPath []byte
		actualPath, oldValueHash = smt.th.parseLeaf(oldLeafData)
		commonPrefixCount = countCommonPrefix(path, actualPath)
	}
	// ASK(reviewer): I don't fully understand why the # of bits is the max depth - depends on the k-ary of the tree
	if commonPrefixCount != smt.depth() {
		// TODO: Need to understand / visualize the business logic here too
		if getBitAtFromMSB(path, commonPrefixCount) == right {
			currentHash, currentData = smt.th.digestNode(pathNodes[0], currentData)
		} else {
			currentHash, currentData = smt.th.digestNode(currentData, pathNodes[0])
		}

		if err := smt.nodes.Set(currentHash, currentData); err != nil {
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
		// TODO: Need to understand / visualize the different between path & pathNodes
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

// Get all the side nodes (a.k.a. sibling nodes) for a given path from a given root.
func (smt *SparseMerkleTree) sideNodesForRoot(path, root []byte) (sideNodes, pathNodes [][]byte, nodeData, sideNode []byte, err error) {
	// Side nodes for the path. Nodes are inserted in reverse order, then the
	// slice is reversed at the end.
	smtDepth := smt.depth()
	sideNodes = make([][]byte, 0, smtDepth) // ASK(reviewer): this should be a function of the k-ary of the tree, not the depth
	pathNodes = make([][]byte, 0, smtDepth)
	pathNodes = append(pathNodes, root)

	if bytes.Equal(root, smt.th.placeholder()) {
		// If the root is a placeholder, there are no sideNodes to return.
		// Let the "actual path" be the input path.
		return sideNodes, pathNodes, nil, nil, nil
	}

	currentData, err := smt.nodes.Get(root)
	if err != nil {
		return nil, nil, nil, nil, err
	} else if smt.th.isLeaf(currentData) {
		// If the root is a leaf, there are no sideNodes to return.
		return sideNodes, pathNodes, currentData, nil, nil
	}

	var nodeHash []byte

	for i := 0; i < smtDepth; i++ {
		leftNode, rightNode := smt.th.parseNode(currentData)

		// Get sideNode depending on whether the path bit is on or off.
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

	sideNodes = reverseByteSlices(sideNodes)
	pathNodes = reverseByteSlices(pathNodes)

	return sideNodes, pathNodes, currentData, sideNode, nil
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
	path := smt.th.path(key)
	sideNodes, pathNodes, leafData, sideNode, err := smt.sideNodesForRoot(path, root)
	if err != nil {
		return SparseMerkleProof{}, err
	}

	var siblingData []byte
	if isUpdatable {
		siblingData, err = smt.nodes.Get(sideNode)
		if err != nil {
			return SparseMerkleProof{}, err
		}
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
		actualPath, _ := smt.th.parseLeaf(leafData)
		if !bytes.Equal(actualPath, path) {
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
	compactedProof, err := CompactProof(proof, smt.th.hasher)
	return compactedProof, err
}
