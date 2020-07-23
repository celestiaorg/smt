package smt

import (
	"bytes"
	//"errors"
	"hash"
)

// SparseMerkleProof is a Merkle proof for a element in a SparseMerkleTree.
type SparseMerkleProof struct {
	// SideNodes is an array of the sibling nodes leading up to the leaf of the proof.
	SideNodes [][]byte

	// NonMembershipLeafData is the data of the unrelated leaf at the position of the key being proven, in the case of a non-membership proof.
	NonMembershipLeafData []byte
}

func (proof *SparseMerkleProof) sanityCheck(th *treeHasher) bool {
	// Do a basic sanity check on the proof, so that a malicious proof cannot cause the program to fatally exit or cause a CPU DoS attack.
	if len(proof.SideNodes) > th.pathSize()*8 || // Check that number of sidenodes is not greater than path size.
		(proof.NonMembershipLeafData != nil && len(proof.NonMembershipLeafData) != len(leafPrefix)+th.pathSize()+th.hasher.Size()) { // Check that leaf data is the correct size, before we parse it.
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
			actualPath, dataHash := th.parseLeaf(proof.NonMembershipLeafData)
			if bytes.Equal(actualPath, path) {
				// This is not an unrelated leaf; non-membership proof failed.
				return false
			}
			currentHash, _ = th.digestLeaf(actualPath, dataHash)
		}
	} else { // Membership proof.
		dataHash := th.digest(value)
		currentHash, _ = th.digestLeaf(path, dataHash)
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
/*func VerifyCompactProof(proof [][]byte, root []byte, key []byte, value []byte, hasher hash.Hash) bool {
	decompactedProof, err := DecompactProof(proof, hasher)
	if err != nil {
		return false
	}
	return VerifyProof(decompactedProof, root, key, value, hasher)
}

// CompactProof compacts a proof, to reduce its size.
func CompactProof(proof [][]byte, hasher hash.Hash) ([][]byte, error) {
	if len(proof) != hasher.Size()*8 {
		return nil, errors.New("bad proof size")
	}

	bits := emptyBytes(hasher.Size())
	var compactProof [][]byte
	for i := 0; i < hasher.Size()*8; i++ {
		node := make([]byte, hasher.Size())
		copy(node, proof[i])
		if bytes.Compare(node, defaultNodes(hasher)[i]) == 0 {
			setBit(bits, i)
		} else {
			compactProof = append(compactProof, node)
		}
	}
	return append([][]byte{bits}, compactProof...), nil
}

// DecompactProof decompacts a proof, so that it can be used for VerifyProof.
func DecompactProof(proof [][]byte, hasher hash.Hash) ([][]byte, error) {
	if len(proof) == 0 ||
		len(proof[0]) != hasher.Size() ||
		len(proof) != (hasher.Size()*8-countSetBits(proof[0]))+1 {
		return nil, errors.New("invalid proof size")
	}

	decompactedProof := make([][]byte, hasher.Size()*8)
	bits := proof[0]
	compactProof := proof[1:]
	position := 0
	for i := 0; i < hasher.Size()*8; i++ {
		if hasBit(bits, i) == 1 {
			decompactedProof[i] = defaultNodes(hasher)[i]
		} else {
			decompactedProof[i] = compactProof[position]
			position++
		}
	}
	return decompactedProof, nil
}*/
