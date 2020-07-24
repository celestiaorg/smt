package smt

import (
	"bytes"
	"errors"
	"hash"
	"math"
)

// SparseMerkleProof is a Merkle proof for a element in a SparseMerkleTree.
type SparseMerkleProof struct {
	// SideNodes is an array of the sibling nodes leading up to the leaf of the proof.
	SideNodes [][]byte

	// NonMembershipLeafData is the data of the unrelated leaf at the position
	// of the key being proven, in the case of a non-membership proof.
	NonMembershipLeafData []byte

	// BitMask, in the case of a compact proof, is a bit mask of the sidenodes
	// of the proof where an on-bit indicates that the sidenode at the bit's
	// index is a placeholder. This is only set if the proof is compact.
	BitMask []byte

	// NumSideNodes, in the case of a compact proof, indicates the number of
	// sidenodes in the proof when decompacted. This is only set if the proof is compact.
	NumSideNodes int
}

func (proof *SparseMerkleProof) sanityCheck(th *treeHasher) bool {
	// Do a basic sanity check on the proof, so that a malicious proof cannot
	// cause the verifier to fatally exit (e.g. due to an index out-of-range
	// error) or cause a CPU DoS attack.
	//
	// We do not check the size of each sidenode, as if the size is incorrect,
	// the proof will fail anyway as the recomputed root will not match.

	// Check that the number of supplied sidenodes does not exceed the maximum possible.
	if len(proof.SideNodes) > th.pathSize()*8 ||

		// Check that leaf data for non-membership proofs is the correct size.
		(proof.NonMembershipLeafData != nil && len(proof.NonMembershipLeafData) != len(leafPrefix)+th.pathSize()+th.hasher.Size()) ||

		// Compact proofs: check that NumSideNodes is within the right range.
		proof.NumSideNodes < 0 ||
		proof.NumSideNodes > th.pathSize()*8 ||

		// Compact proofs: check that the length of the bit mask is as expected
		// according to NumSideNodes.
		len(proof.BitMask) != int(math.Ceil(float64(proof.NumSideNodes)/float64(8))) ||

		// Compact proofs: check that the correct number of sidenodes have been
		// supplied according to the bit mask.
		(proof.NumSideNodes > 0 && len(proof.SideNodes) != proof.NumSideNodes-countSetBits(proof.BitMask)) {
		return false
	}

	return true
}

// VerifyProof verifies a Merkle proof.
func VerifyProof(proof SparseMerkleProof, root []byte, key []byte, value []byte, hasher hash.Hash) bool {
	th := newTreeHasher(hasher)
	path := th.path(key)

	if !proof.sanityCheck(th) {
		return false
	}

	// Determine what the leaf hash should be.
	var currentHash []byte
	if bytes.Equal(value, defaultValue) { // Non-membership proof.
		if proof.NonMembershipLeafData == nil { // Leaf is a placeholder value.
			currentHash = th.placeholder()
		} else { // Leaf is an unrelated leaf.
			actualPath, valueHash := th.parseLeaf(proof.NonMembershipLeafData)
			if bytes.Equal(actualPath, path) {
				// This is not an unrelated leaf; non-membership proof failed.
				return false
			}
			currentHash, _ = th.digestLeaf(actualPath, valueHash)
		}
	} else { // Membership proof.
		valueHash := th.digest(value)
		currentHash, _ = th.digestLeaf(path, valueHash)
	}

	// Recompute root.
	for i := len(proof.SideNodes) - 1; i >= 0; i-- {
		node := make([]byte, th.pathSize())
		copy(node, proof.SideNodes[i])
		if len(node) != th.pathSize() {
			return false
		}
		if hasBit(path, i) == right {
			currentHash, _ = th.digestNode(node, currentHash)
		} else {
			currentHash, _ = th.digestNode(currentHash, node)
		}
	}

	return bytes.Compare(currentHash, root) == 0
}

// VerifyCompactProof verifies a compacted Merkle proof.
func VerifyCompactProof(proof SparseMerkleProof, root []byte, key []byte, value []byte, hasher hash.Hash) bool {
	decompactedProof, err := DecompactProof(proof, hasher)
	if err != nil {
		return false
	}
	return VerifyProof(decompactedProof, root, key, value, hasher)
}

// CompactProof compacts a proof, to reduce its size.
func CompactProof(proof SparseMerkleProof, hasher hash.Hash) (SparseMerkleProof, error) {
	th := newTreeHasher(hasher)

	if !proof.sanityCheck(th) {
		return SparseMerkleProof{}, errors.New("bad proof")
	}

	bitMask := emptyBytes(int(math.Ceil(float64(len(proof.SideNodes)) / float64(8))))
	var compactedSideNodes [][]byte
	for i := 0; i < len(proof.SideNodes); i++ {
		node := make([]byte, th.hasher.Size())
		copy(node, proof.SideNodes[i])
		if bytes.Equal(node, th.placeholder()) {
			setBit(bitMask, i)
		} else {
			compactedSideNodes = append(compactedSideNodes, node)
		}
	}

	return SparseMerkleProof{
		SideNodes:             compactedSideNodes,
		NonMembershipLeafData: proof.NonMembershipLeafData,
		BitMask:               bitMask,
		NumSideNodes:          len(proof.SideNodes),
	}, nil
}

// DecompactProof decompacts a proof, so that it can be used for VerifyProof.
func DecompactProof(proof SparseMerkleProof, hasher hash.Hash) (SparseMerkleProof, error) {
	th := newTreeHasher(hasher)

	if !proof.sanityCheck(th) {
		return SparseMerkleProof{}, errors.New("bad proof")
	}

	decompactedSideNodes := make([][]byte, proof.NumSideNodes)
	position := 0
	for i := 0; i < proof.NumSideNodes; i++ {
		if hasBit(proof.BitMask, i) == 1 {
			decompactedSideNodes[i] = th.placeholder()
		} else {
			decompactedSideNodes[i] = proof.SideNodes[position]
			position += 1
		}
	}

	return SparseMerkleProof{
		SideNodes:             decompactedSideNodes,
		NonMembershipLeafData: proof.NonMembershipLeafData,
	}, nil
}
