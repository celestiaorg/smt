package smt

import (
	"bytes"
	"hash"
	"math"
)

// SparseMerkleProof is a Merkle proof for an element in a SparseMerkleTree.
type SparseMerkleProof struct {
	// SideNodes is an array of the sibling nodes leading up to the leaf of the proof.
	SideNodes [][]byte

	// NonMembershipLeafData is the data of the unrelated leaf at the position
	// of the key being proven, in the case of a non-membership proof. For
	// membership proofs, is nil.
	NonMembershipLeafData []byte

	// SiblingData is the data of the sibling node to the leaf being proven,
	// required for updatable proofs. For unupdatable proofs, is nil.
	SiblingData []byte
}

func (proof *SparseMerkleProof) sanityCheck(th *treeHasher) bool {
	// Do a basic sanity check on the proof, so that a malicious proof cannot
	// cause the verifier to fatally exit (e.g. due to an index out-of-range
	// error) or cause a CPU DoS attack.

	// Check that the number of supplied sidenodes does not exceed the maximum possible.
	if len(proof.SideNodes) > th.pathSize()*8 ||

		// Check that leaf data for non-membership proofs is the correct size.
		(proof.NonMembershipLeafData != nil && len(proof.NonMembershipLeafData) != len(leafPrefix)+th.pathSize()+th.hasher.Size()) {
		return false
	}

	// Check that all supplied sidenodes are the correct size.
	for _, v := range proof.SideNodes {
		if len(v) != th.hasher.Size() {
			return false
		}
	}

	// Check that the sibling data hashes to the first side node if not nil
	if proof.SiblingData != nil {
		siblingHash := th.digest(proof.SiblingData)
		if proof.SideNodes != nil && len(proof.SideNodes) > 0 {
			if !bytes.Equal(proof.SideNodes[0], siblingHash) {
				return false
			}
		}
	}

	return true
}

// SparseCompactMerkleProof is a compact Merkle proof for an element in a SparseMerkleTree.
type SparseCompactMerkleProof struct {
	// SideNodes is an array of the sibling nodes leading up to the leaf of the proof.
	SideNodes [][]byte

	// NonMembershipLeafData is the data of the unrelated leaf at the position
	// of the key being proven, in the case of a non-membership proof. For
	// membership proofs, is nil.
	NonMembershipLeafData []byte

	// BitMask, in the case of a compact proof, is a bit mask of the sidenodes
	// of the proof where an on-bit indicates that the sidenode at the bit's
	// index is a placeholder. This is only set if the proof is compact.
	BitMask []byte

	// NumSideNodes, in the case of a compact proof, indicates the number of
	// sidenodes in the proof when decompacted. This is only set if the proof is compact.
	NumSideNodes int

	// SiblingData is the data of the sibling node to the leaf being proven,
	// required for updatable proofs. For unupdatable proofs, is nil.
	SiblingData []byte
}

func (proof *SparseCompactMerkleProof) sanityCheck(th *treeHasher) bool {
	// Do a basic sanity check on the proof on the fields of the proof specific to
	// the compact proof only.
	//
	// When the proof is de-compacted and verified, the sanity check for the
	// de-compacted proof should be executed.

	// Compact proofs: check that NumSideNodes is within the right range.
	if proof.NumSideNodes < 0 || proof.NumSideNodes > th.pathSize()*8 ||

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
	result, _ := verifyProofWithUpdates(proof, root, key, value, hasher)
	return result
}

func verifyProofWithUpdates(proof SparseMerkleProof, root []byte, key []byte, value []byte, hasher hash.Hash) (bool, [][][]byte) {
	th := newTreeHasher(hasher)
	path := th.path(key)

	if !proof.sanityCheck(th) {
		return false, nil
	}

	var updates [][][]byte

	// Determine what the leaf hash should be.
	var currentHash, currentData []byte
	if bytes.Equal(value, defaultValue) { // Non-membership proof.
		if proof.NonMembershipLeafData == nil { // Leaf is a placeholder value.
			currentHash = th.placeholder()
		} else { // Leaf is an unrelated leaf.
			actualPath, valueHash := th.parseLeaf(proof.NonMembershipLeafData)
			if bytes.Equal(actualPath, path) {
				// This is not an unrelated leaf; non-membership proof failed.
				return false, nil
			}
			currentHash, currentData = th.digestLeaf(actualPath, valueHash)

			update := make([][]byte, 2)
			update[0], update[1] = currentHash, currentData
			updates = append(updates, update)
		}
	} else { // Membership proof.
		valueHash := th.digest(value)
		currentHash, currentData = th.digestLeaf(path, valueHash)
		update := make([][]byte, 2)
		update[0], update[1] = currentHash, currentData
		updates = append(updates, update)
	}

	// Recompute root.
	for i := 0; i < len(proof.SideNodes); i++ {
		node := make([]byte, th.pathSize())
		copy(node, proof.SideNodes[i])

		if getBitAtFromMSB(path, len(proof.SideNodes)-1-i) == right {
			currentHash, currentData = th.digestNode(node, currentHash)
		} else {
			currentHash, currentData = th.digestNode(currentHash, node)
		}

		update := make([][]byte, 2)
		update[0], update[1] = currentHash, currentData
		updates = append(updates, update)
	}

	return bytes.Equal(currentHash, root), updates
}

// VerifyCompactProof verifies a compacted Merkle proof.
func VerifyCompactProof(proof SparseCompactMerkleProof, root []byte, key []byte, value []byte, hasher hash.Hash) bool {
	decompactedProof, err := DecompactProof(proof, hasher)
	if err != nil {
		return false
	}
	return VerifyProof(decompactedProof, root, key, value, hasher)
}

// CompactProof compacts a proof, to reduce its size.
func CompactProof(proof SparseMerkleProof, hasher hash.Hash) (SparseCompactMerkleProof, error) {
	th := newTreeHasher(hasher)

	if !proof.sanityCheck(th) {
		return SparseCompactMerkleProof{}, ErrBadProof
	}

	bitMask := emptyBytes(int(math.Ceil(float64(len(proof.SideNodes)) / float64(8))))
	var compactedSideNodes [][]byte
	for i := 0; i < len(proof.SideNodes); i++ {
		node := make([]byte, th.hasher.Size())
		copy(node, proof.SideNodes[i])
		if bytes.Equal(node, th.placeholder()) {
			setBitAtFromMSB(bitMask, i)
		} else {
			compactedSideNodes = append(compactedSideNodes, node)
		}
	}

	return SparseCompactMerkleProof{
		SideNodes:             compactedSideNodes,
		NonMembershipLeafData: proof.NonMembershipLeafData,
		BitMask:               bitMask,
		NumSideNodes:          len(proof.SideNodes),
		SiblingData:           proof.SiblingData,
	}, nil
}

// DecompactProof decompacts a proof, so that it can be used for VerifyProof.
func DecompactProof(proof SparseCompactMerkleProof, hasher hash.Hash) (SparseMerkleProof, error) {
	th := newTreeHasher(hasher)

	if !proof.sanityCheck(th) {
		return SparseMerkleProof{}, ErrBadProof
	}

	decompactedSideNodes := make([][]byte, proof.NumSideNodes)
	position := 0
	for i := 0; i < proof.NumSideNodes; i++ {
		if getBitAtFromMSB(proof.BitMask, i) == 1 {
			decompactedSideNodes[i] = th.placeholder()
		} else {
			decompactedSideNodes[i] = proof.SideNodes[position]
			position++
		}
	}

	return SparseMerkleProof{
		SideNodes:             decompactedSideNodes,
		NonMembershipLeafData: proof.NonMembershipLeafData,
		SiblingData:           proof.SiblingData,
	}, nil
}
