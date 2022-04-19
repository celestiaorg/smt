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

func newBaseSMT(hasher hash.Hash, options ...Option) BaseSMT {
	smt := BaseSMT{th: *newTreeHasher(hasher)}
	smt.ph = &smt.th
	for _, option := range options {
		option(&smt)
	}
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
