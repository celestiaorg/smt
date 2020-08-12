package smt

import (
	"bytes"
	"crypto/sha256"
	"hash"
	"math/rand"
	"testing"
)

// Test base case Merkle proof operations.
func TestProofsBasic(t *testing.T) {
	var sm *SimpleMap
	var smt *SparseMerkleTree
	var proof SparseMerkleProof
	var result bool
	var root []byte
	var err error

	sm = NewSimpleMap()
	smt = NewSparseMerkleTree(sm, sha256.New())

	// Generate and verify a proof on an empty key.
	proof, err = smt.Prove([]byte("testKey3"))
	checkCompactEquivalence(t, proof, smt.th.hasher)
	if err != nil {
		t.Error("error returned when trying to prove inclusion on empty key")
	}
	result = VerifyProof(proof, bytes.Repeat([]byte{0}, smt.th.hasher.Size()), []byte("testKey3"), defaultValue, smt.th.hasher)
	if !result {
		t.Error("valid proof on empty key failed to verify")
	}
	result = VerifyProof(proof, root, []byte("testKey3"), []byte("badValue"), smt.th.hasher)
	if result {
		t.Error("invalid proof verification returned true")
	}

	// Add a key, generate and verify a Merkle proof.
	root, _ = smt.Update([]byte("testKey"), []byte("testValue"))
	proof, err = smt.Prove([]byte("testKey"))
	checkCompactEquivalence(t, proof, smt.th.hasher)
	if err != nil {
		t.Error("error returned when trying to prove inclusion")
	}
	result = VerifyProof(proof, root, []byte("testKey"), []byte("testValue"), smt.th.hasher)
	if !result {
		t.Error("valid proof failed to verify")
	}
	result = VerifyProof(proof, root, []byte("testKey"), []byte("badValue"), smt.th.hasher)
	if result {
		t.Error("invalid proof verification returned true")
	}

	// Add a key, generate and verify both Merkle proofs.
	root, _ = smt.Update([]byte("testKey2"), []byte("testValue"))
	proof, err = smt.Prove([]byte("testKey"))
	checkCompactEquivalence(t, proof, smt.th.hasher)
	if err != nil {
		t.Error("error returned when trying to prove inclusion")
	}
	result = VerifyProof(proof, root, []byte("testKey"), []byte("testValue"), smt.th.hasher)
	if !result {
		t.Error("valid proof failed to verify")
	}
	result = VerifyProof(proof, root, []byte("testKey"), []byte("badValue"), smt.th.hasher)
	if result {
		t.Error("invalid proof verification returned true")
	}
	result = VerifyProof(randomiseProof(proof), root, []byte("testKey"), []byte("testValue"), smt.th.hasher)
	if result {
		t.Error("invalid proof verification returned true")
	}

	proof, err = smt.Prove([]byte("testKey2"))
	checkCompactEquivalence(t, proof, smt.th.hasher)
	if err != nil {
		t.Error("error returned when trying to prove inclusion")
	}
	result = VerifyProof(proof, root, []byte("testKey2"), []byte("testValue"), smt.th.hasher)
	if !result {
		t.Error("valid proof failed to verify")
	}
	result = VerifyProof(proof, root, []byte("testKey2"), []byte("badValue"), smt.th.hasher)
	if result {
		t.Error("invalid proof verification returned true")
	}
	result = VerifyProof(randomiseProof(proof), root, []byte("testKey2"), []byte("testValue"), smt.th.hasher)
	if result {
		t.Error("invalid proof verification returned true")
	}

	// Try proving a default value for a non-default leaf.
	th := newTreeHasher(smt.th.hasher)
	_, leafData := th.digestLeaf(th.path([]byte("testKey2")), th.digest([]byte("testValue")))
	proof = SparseMerkleProof{
		SideNodes:             proof.SideNodes,
		NonMembershipLeafData: leafData,
	}
	result = VerifyProof(proof, root, []byte("testKey2"), defaultValue, smt.th.hasher)
	if result {
		t.Error("invalid proof verification returned true")
	}

	// Generate and verify a proof on an empty key.
	proof, err = smt.Prove([]byte("testKey3"))
	checkCompactEquivalence(t, proof, smt.th.hasher)
	if err != nil {
		t.Error("error returned when trying to prove inclusion on empty key")
	}
	result = VerifyProof(proof, root, []byte("testKey3"), defaultValue, smt.th.hasher)
	if !result {
		t.Error("valid proof on empty key failed to verify")
	}
	result = VerifyProof(proof, root, []byte("testKey3"), []byte("badValue"), smt.th.hasher)
	if result {
		t.Error("invalid proof verification returned true")
	}
	result = VerifyProof(randomiseProof(proof), root, []byte("testKey3"), defaultValue, smt.th.hasher)
	if result {
		t.Error("invalid proof verification returned true")
	}
}

// Test sanity check cases for non-compact proofs.
func TestProofsSanityCheck(t *testing.T) {
	sm := NewSimpleMap()
	smt := NewSparseMerkleTree(sm, sha256.New())
	th := &smt.th

	smt.Update([]byte("testKey1"), []byte("testValue1"))
	smt.Update([]byte("testKey2"), []byte("testValue2"))
	smt.Update([]byte("testKey3"), []byte("testValue3"))
	root, _ := smt.Update([]byte("testKey4"), []byte("testValue4"))

	// Case: invalid number of sidenodes.
	proof, _ := smt.Prove([]byte("testKey1"))
	sideNodes := make([][]byte, smt.th.pathSize()*8+1)
	for i := range sideNodes {
		sideNodes[i] = proof.SideNodes[0]
	}
	proof.SideNodes = sideNodes
	if proof.sanityCheck(th) {
		t.Error("sanity check incorrectly passed")
	}
	result := VerifyProof(proof, root, []byte("testKey1"), []byte("testValue1"), smt.th.hasher)
	if result {
		t.Error("invalid proof verification returned true")
	}

	// Case: incorrect size for NonMembershipLeafData.
	proof, _ = smt.Prove([]byte("testKey1"))
	proof.NonMembershipLeafData = make([]byte, 1)
	if proof.sanityCheck(th) {
		t.Error("sanity check incorrectly passed")
	}
	result = VerifyProof(proof, root, []byte("testKey1"), []byte("testValue1"), smt.th.hasher)
	if result {
		t.Error("invalid proof verification returned true")
	}

	// Case: unexpected sidenode size.
	proof, _ = smt.Prove([]byte("testKey1"))
	proof.SideNodes[0] = make([]byte, 1)
	if proof.sanityCheck(th) {
		t.Error("sanity check incorrectly passed")
	}
	result = VerifyProof(proof, root, []byte("testKey1"), []byte("testValue1"), smt.th.hasher)
	if result {
		t.Error("invalid proof verification returned true")
	}
}

// Test sanity check cases for compact proofs.
func TestCompactProofsSanityCheck(t *testing.T) {
	sm := NewSimpleMap()
	smt := NewSparseMerkleTree(sm, sha256.New())
	th := &smt.th

	smt.Update([]byte("testKey1"), []byte("testValue1"))
	smt.Update([]byte("testKey2"), []byte("testValue2"))
	smt.Update([]byte("testKey3"), []byte("testValue3"))
	root, _ := smt.Update([]byte("testKey4"), []byte("testValue4"))

	// Case (compact proofs): NumSideNodes out of range.
	proof, _ := smt.ProveCompact([]byte("testKey1"))
	proof.NumSideNodes = -1
	if proof.sanityCheck(th) {
		t.Error("sanity check incorrectly passed")
	}
	proof.NumSideNodes = th.pathSize()*8 + 1
	if proof.sanityCheck(th) {
		t.Error("sanity check incorrectly passed")
	}
	result := VerifyCompactProof(proof, root, []byte("testKey1"), []byte("testValue1"), smt.th.hasher)
	if result {
		t.Error("invalid proof verification returned true")
	}

	// Case (compact proofs): unexpected bit mask length.
	proof, _ = smt.ProveCompact([]byte("testKey1"))
	proof.NumSideNodes = 1
	if proof.sanityCheck(th) {
		t.Error("sanity check incorrectly passed")
	}
	result = VerifyCompactProof(proof, root, []byte("testKey1"), []byte("testValue1"), smt.th.hasher)
	if result {
		t.Error("invalid proof verification returned true")
	}

	// Case (compact proofs): unexpected number of sidenodes for number of side nodes.
	proof, _ = smt.ProveCompact([]byte("testKey1"))
	proof.SideNodes = proof.SideNodes[:1]
	if proof.sanityCheck(th) {
		t.Error("sanity check incorrectly passed")
	}
	result = VerifyCompactProof(proof, root, []byte("testKey1"), []byte("testValue1"), smt.th.hasher)
	if result {
		t.Error("invalid proof verification returned true")
	}
}

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
func checkCompactEquivalence(t *testing.T, proof SparseMerkleProof, hasher hash.Hash) {
	compactedProof, err := CompactProof(proof, hasher)
	if err != nil {
		t.Error("failed to compact proof")
	}
	decompactedProof, err := DecompactProof(compactedProof, hasher)
	if err != nil {
		t.Error("failed to decompact proof")
	}

	for i, sideNode := range proof.SideNodes {
		if !bytes.Equal(decompactedProof.SideNodes[i], sideNode) {
			t.Error("de-compacted proof does not match original proof")
		}
	}

	if !bytes.Equal(proof.NonMembershipLeafData, decompactedProof.NonMembershipLeafData) {
		t.Error("de-compacted proof does not match original proof")
	}
}
