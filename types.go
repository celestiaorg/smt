package smt

import (
	"errors"
	"hash"
)

const (
	left = 0
)

var (
	defaultValue []byte = nil

	ErrKeyNotPresent = errors.New("key already empty")
)

// SparseMerkleTree represents a Sparse Merkle tree.
type SparseMerkleTree interface {
	// Update inserts a value into the SMT.
	Update(key, value []byte) error
	// Delete deletes a value from the SMT. Raises an error if the key is not present.
	Delete(key []byte) error
	// Get descends the tree to access a value. Returns nil if key is not present.
	Get(key []byte) ([]byte, error)
	// Root computes the Merkle root digest.
	Root() []byte
	// Prove computes a Merkle proof of membership or non-membership of a key.
	Prove(key []byte) (SparseMerkleProof, error)
	// Commit saves the tree's state to its persistent storage.
	Commit() error

	Spec() *TreeSpec
}

// TreeSpec defines the specification of a specific tree, including hash functions
// for leaf paths and stored values, and max tree depth.
type TreeSpec struct {
	th treeHasher
	ph PathHasher
	vh ValueHasher
}

func newTreeSpec(hasher hash.Hash) TreeSpec {
	spec := TreeSpec{th: *newTreeHasher(hasher)}
	spec.ph = &pathHasher{spec.th}
	spec.vh = &valueHasher{spec.th}
	return spec
}

func (spec *TreeSpec) Spec() *TreeSpec { return spec }

func (spec *TreeSpec) depth() int { return spec.ph.PathSize() * 8 }
func (spec *TreeSpec) digestValue(data []byte) []byte {
	if spec.vh == nil {
		return data
	}
	return spec.vh.HashValue(data)
}

func (spec *TreeSpec) serialize(node treeNode) (data []byte) {
	switch n := node.(type) {
	case *lazyNode:
		panic("serialize(lazyNode)")
	case *leafNode:
		return encodeLeaf(n.path, n.valueHash)
	case *innerNode:
		lchild := spec.hashNode(n.leftChild)
		rchild := spec.hashNode(n.rightChild)
		return encodeInner(lchild, rchild)
	case *extensionNode:
		child := spec.hashNode(n.child)
		return encodeExtension(n.pathBounds, n.path, child)
	}
	return nil
}

func (spec *TreeSpec) hashNode(node treeNode) []byte {
	if node == nil {
		return spec.th.placeholder()
	}
	var cache *[]byte
	switch n := node.(type) {
	case *lazyNode:
		return n.digest
	case *leafNode:
		cache = &n.digest
	case *innerNode:
		cache = &n.digest
	case *extensionNode:
		if n.digest == nil {
			n.digest = spec.hashNode(n.expand())
		}
		return n.digest
	}
	if *cache == nil {
		*cache = spec.th.digest(spec.serialize(node))
	}
	return *cache
}
