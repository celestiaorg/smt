package smt

import(
    "hash"
)

type DeepSparseMerkleSubTree struct {
    *SparseMerkleTree
}

func NewDeepSparseMerkleSubTree(ms MapStore, hasher hash.Hash) *DeepSparseMerkleSubTree {
    smt := &SparseMerkleTree{
        hasher: hasher,
        ms: ms,
    }

    return &DeepSparseMerkleSubTree{SparseMerkleTree: smt}
}

func (dsmst *DeepSparseMerkleSubTree) AddProof(proof [][]byte, key []byte, value []byte) ([]byte, error) {
    return dsmst.updateWithSideNodes(dsmst.digest(key), value, proof)
}
