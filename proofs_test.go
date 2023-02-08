package smt

import (
	"bytes"
	"math/rand"
	"testing"
)

func randomiseProof(proof SparseMerkleProof) SparseMerkleProof {
	sideNodes := make([][]byte, len(proof.SideNodes))
	for i := range sideNodes {
		sideNodes[i] = make([]byte, len(proof.SideNodes[i]))
		rand.Read(sideNodes[i])
	}
	return SparseMerkleProof{
		SideNodes:             sideNodes,
		NonMembershipLeafData: proof.NonMembershipLeafData,
	}
}

// Check that a non-compact proof is equivalent to the proof returned when it is compacted and de-compacted.
func checkCompactEquivalence(t *testing.T, proof SparseMerkleProof, base *TreeSpec) {
	t.Helper()
	compactedProof, err := CompactProof(proof, base)
	if err != nil {
		t.Fatalf("failed to compact proof: %v", err)
	}
	decompactedProof, err := DecompactProof(compactedProof, base)
	if err != nil {
		t.Fatalf("failed to decompact proof: %v", err)
	}

	for i, sideNode := range proof.SideNodes {
		if !bytes.Equal(decompactedProof.SideNodes[i], sideNode) {
			t.Fatalf("de-compacted proof does not match original proof")
		}
	}

	if !bytes.Equal(proof.NonMembershipLeafData, decompactedProof.NonMembershipLeafData) {
		t.Fatalf("de-compacted proof does not match original proof")
	}
}
