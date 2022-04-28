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
	// Save commits the tree's state to its persistent storage.
	Save() error

	base() *BaseSMT
}

type BaseSMT struct {
	th treeHasher
	ph PathHasher
	vh ValueHasher
}

func newBaseSMT(hasher hash.Hash) BaseSMT {
	smt := BaseSMT{th: *newTreeHasher(hasher)}
	smt.ph = &pathHasher{smt.th}
	smt.vh = &smt.th
	return smt
}

func (smt *BaseSMT) base() *BaseSMT { return smt }
func (smt *BaseSMT) depth() int     { return smt.ph.PathSize() * 8 }
func (smt *BaseSMT) digestValue(data []byte) []byte {
	if smt.vh == nil {
		return data
	}
	return smt.vh.digest(data)
}

func (smt *BaseSMT) serialize(node treeNode) (data []byte) {
	switch n := node.(type) {
	case *lazyNode:
		panic("serialize(lazyNode)")
	case *leafNode:
		return encodeLeaf(n.path, n.valueHash)
	case *innerNode:
		lchild := smt.hashNode(n.leftChild)
		rchild := smt.hashNode(n.rightChild)
		return encodeInner(lchild, rchild)
	case *extensionNode:
		child := smt.hashNode(n.child)
		return encodeExtension(n.pathBounds, n.path, child)
	}
	return nil
}

func (smt *BaseSMT) hashNode(node treeNode) []byte {
	if node == nil {
		return smt.th.placeholder()
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
			n.digest = smt.hashNode(n.expand())
		}
		return n.digest
	}
	if *cache == nil {
		*cache = smt.th.digest(smt.serialize(node))
	}
	return *cache
}
