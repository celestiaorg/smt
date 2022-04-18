package smt

import (
	"errors"
)

const (
	left = 0
)

var (
	defaultValue []byte = nil

	errKeyNotPresent = errors.New("key already empty")
)

// SparseMerkleTree represents a Sparse Merkle tree.
type SparseMerkleTree interface {
	// Update inserts a value into the SMT.
	Update(key, value []byte) error
	// Delete deletes a value from the SMT. Raises an error if the key is not present.
	Delete(key []byte) error
	// GetDescend descends the tree to access a value. Returns nil if key is not present.
	GetDescend(key []byte) ([]byte, error)
	// Root computes the Merkle root digest.
	Root() []byte
	// Prove computes a Merkle proof of membership or non-membership of a key.
	Prove(key []byte) (SparseMerkleProof, error)

	base() *BaseSMT
}

type BaseSMT struct {
	nodes MapStore
	th    *treeHasher
	ph    PathHasher
}

func (smt *BaseSMT) base() *BaseSMT { return smt }

func (smt *BaseSMT) depth() int { return smt.ph.Size() * 8 }
