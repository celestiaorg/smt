package smt

import (
	"bytes"
	"crypto/sha256"
	"hash"
	"math/rand"
	"testing"
)

func TestProofsKeySizeChecks(t *testing.T) {
	hasher := sha256.New()
	keySize := len([]byte("testKey1"))
	smn, _ := NewSimpleMap(hasher.Size())
	smv, _ := NewSimpleMap(keySize)
	smt := NewSparseMerkleTree(smn, smv, hasher)

	_, err := smt.Update([]byte("testKey1"), []byte("testValue1"))
	if err != nil {
		t.Errorf("couldn't update smt. exception: %v", err)
	}

	_, err = smt.Update([]byte("testKey2"), []byte("testValue2"))
	if err != nil {
		t.Errorf("couldn't update smt. exception: %v", err)
	}

	proof, err := smt.Prove([]byte("testKey1"))
	if err != nil {
		t.Errorf("couldn't prove existing key. Actual exception: %v", err)
	}

	proved := VerifyProof(proof, smt.Root(), randomBytes(keySize+1), []byte("testValue1"), hasher, smt.values.GetKeySize())
	if proved {
		t.Errorf("shouldn't have been able to verify prove a `keySize + 1`.")
	}

	proved = VerifyProof(proof, smt.Root(), randomBytes(keySize-1), []byte("testValue1"), hasher, smt.values.GetKeySize())
	if proved {
		t.Errorf("shouldn't have been able to verify prove a `keySize - 1`.")
	}

	_, err = smt.ProveCompact(randomBytes(keySize + 1))
	if err == nil {
		t.Errorf("shouldn't have been able to prove compact for a `keySize + 1`.")
	}

	_, err = smt.ProveCompact(randomBytes(keySize - 1))
	if err == nil {
		t.Errorf("shouldn't have been able to prove compact for a `keySize - 1`.")
	}

	compactProof, err := smt.ProveCompact([]byte("testKey1"))
	if err != nil {
		t.Errorf("couldn't prove compact existing key: %v", err)
	}

	proved = VerifyCompactProof(compactProof, smt.Root(), randomBytes(keySize+1), []byte("testValue1"), sha256.New(), smt.values.GetKeySize())
	if proved {
		t.Errorf("shouldn't have been able to verify compact proof for a `keySize + 1`.")
	}

	proved = VerifyCompactProof(compactProof, smt.Root(), randomBytes(keySize-1), []byte("testValue1"), sha256.New(), smt.values.GetKeySize())
	if proved {
		t.Errorf("shouldn't have been able to verify compact proof for a `keySize - 1`.")
	}
}

// Test base case Merkle proof operations.
func TestProofsBasic(t *testing.T) {
	var smn, smv *SimpleMap
	var smt *SparseMerkleTree
	var proof SparseMerkleProof
	var result bool
	var root []byte
	var err error

	hasher := sha256.New()
	smn, _ = NewSimpleMap(hasher.Size())
	smv, _ = NewSimpleMap(len([]byte("testKey1")))
	smt = NewSparseMerkleTree(smn, smv, hasher)

	// Generate and verify a proof on an empty key.
	proof, err = smt.Prove([]byte("testKey3"))
	checkCompactEquivalence(t, proof, smt.th.hasher, smt.values.GetKeySize())
	if err != nil {
		t.Error("error returned when trying to prove inclusion on empty key")
	}
	result = VerifyProof(proof, bytes.Repeat([]byte{0}, smt.th.hasher.Size()), []byte("testKey3"), defaultValue, smt.th.hasher, smt.values.GetKeySize())
	if !result {
		t.Error("valid proof on empty key failed to verify")
	}
	result = VerifyProof(proof, root, []byte("testKey3"), []byte("badValue"), smt.th.hasher, smt.values.GetKeySize())
	if result {
		t.Error("invalid proof verification returned true")
	}

	// Add a key, generate and verify a Merkle proof.
	root, _ = smt.Update([]byte("testKey1"), []byte("testValue1"))
	proof, err = smt.Prove([]byte("testKey1"))
	checkCompactEquivalence(t, proof, smt.th.hasher, smt.values.GetKeySize())
	if err != nil {
		t.Error("error returned when trying to prove inclusion")
	}
	result = VerifyProof(proof, root, []byte("testKey1"), []byte("testValue1"), smt.th.hasher, smt.values.GetKeySize())
	if !result {
		t.Error("valid proof failed to verify")
	}
	result = VerifyProof(proof, root, []byte("testKey1"), []byte("badValue"), smt.th.hasher, smt.values.GetKeySize())
	if result {
		t.Error("invalid proof verification returned true")
	}

	// Add a key, generate and verify both Merkle proofs.
	root, _ = smt.Update([]byte("testKey2"), []byte("testValue1"))
	proof, err = smt.Prove([]byte("testKey1"))
	checkCompactEquivalence(t, proof, smt.th.hasher, smt.values.GetKeySize())
	if err != nil {
		t.Error("error returned when trying to prove inclusion")
	}
	result = VerifyProof(proof, root, []byte("testKey1"), []byte("testValue1"), smt.th.hasher, smt.values.GetKeySize())
	if !result {
		t.Error("valid proof failed to verify")
	}
	result = VerifyProof(proof, root, []byte("testKey1"), []byte("badValue"), smt.th.hasher, smt.values.GetKeySize())
	if result {
		t.Error("invalid proof verification returned true")
	}
	result = VerifyProof(randomiseProof(proof), root, []byte("testKey1"), []byte("testKey1"), smt.th.hasher, smt.values.GetKeySize())
	if result {
		t.Error("invalid proof verification returned true")
	}

	proof, err = smt.Prove([]byte("testKey2"))
	checkCompactEquivalence(t, proof, smt.th.hasher, smt.values.GetKeySize())
	if err != nil {
		t.Error("error returned when trying to prove inclusion")
	}
	result = VerifyProof(proof, root, []byte("testKey2"), []byte("testValue1"), smt.th.hasher, smt.values.GetKeySize())
	if !result {
		t.Error("valid proof failed to verify")
	}
	result = VerifyProof(proof, root, []byte("testKey2"), []byte("badValue"), smt.th.hasher, smt.values.GetKeySize())
	if result {
		t.Error("invalid proof verification returned true")
	}
	result = VerifyProof(randomiseProof(proof), root, []byte("testKey2"), []byte("testValue1"), smt.th.hasher, smt.values.GetKeySize())
	if result {
		t.Error("invalid proof verification returned true")
	}

	// Try proving a default value for a non-default leaf.
	th := newTreeHasher(smt.th.hasher)
	_, leafData := th.digestLeaf([]byte("testKey2"), th.digest([]byte("testValue1")))
	proof = SparseMerkleProof{
		SideNodes:             proof.SideNodes,
		NonMembershipLeafData: leafData,
	}
	result = VerifyProof(proof, root, []byte("testKey2"), defaultValue, smt.th.hasher, smt.values.GetKeySize())
	if result {
		t.Error("invalid proof verification returned true")
	}

	// Generate and verify a proof on an empty key.
	proof, err = smt.Prove([]byte("testKey3"))
	checkCompactEquivalence(t, proof, smt.th.hasher, smt.values.GetKeySize())
	if err != nil {
		t.Error("error returned when trying to prove inclusion on empty key")
	}
	result = VerifyProof(proof, root, []byte("testKey3"), defaultValue, smt.th.hasher, smt.values.GetKeySize())
	if !result {
		t.Error("valid proof on empty key failed to verify")
	}
	result = VerifyProof(proof, root, []byte("testKey3"), []byte("badValue"), smt.th.hasher, smt.values.GetKeySize())
	if result {
		t.Error("invalid proof verification returned true")
	}
	result = VerifyProof(randomiseProof(proof), root, []byte("testKey3"), defaultValue, smt.th.hasher, smt.values.GetKeySize())
	if result {
		t.Error("invalid proof verification returned true")
	}
}

// Test sanity check cases for non-compact proofs.
func TestProofsSanityCheck(t *testing.T) {
	hasher := sha256.New()
	smn, _ := NewSimpleMap(hasher.Size())
	smv, _ := NewSimpleMap(len([]byte("testKey1")))
	smt := NewSparseMerkleTree(smn, smv, hasher)
	th := &smt.th

	_, _ = smt.Update([]byte("testKey1"), []byte("testValue1"))
	_, _ = smt.Update([]byte("testKey2"), []byte("testValue2"))
	_, _ = smt.Update([]byte("testKey3"), []byte("testValue3"))
	root, _ := smt.Update([]byte("testKey4"), []byte("testValue4"))

	// Case: invalid number of sidenodes.
	proof, _ := smt.Prove([]byte("testKey1"))
	sideNodes := make([][]byte, len([]byte("testKey1"))*8+1)
	for i := range sideNodes {
		sideNodes[i] = proof.SideNodes[0]
	}
	proof.SideNodes = sideNodes
	if proof.sanityCheck(th, smt.values.GetKeySize()) {
		t.Error("sanity check incorrectly passed")
	}
	result := VerifyProof(proof, root, []byte("testKey1"), []byte("testValue1"), smt.th.hasher, smt.values.GetKeySize())
	if result {
		t.Error("invalid proof verification returned true")
	}
	_, err := CompactProof(proof, smt.th.hasher, smt.values.GetKeySize())
	if err == nil {
		t.Error("did not return error when compacting a malformed proof")
	}

	// Case: incorrect size for NonMembershipLeafData.
	proof, _ = smt.Prove([]byte("testKey1"))
	proof.NonMembershipLeafData = make([]byte, 1)
	if proof.sanityCheck(th, smt.values.GetKeySize()) {
		t.Error("sanity check incorrectly passed")
	}
	result = VerifyProof(proof, root, []byte("testKey1"), []byte("testValue1"), smt.th.hasher, smt.values.GetKeySize())
	if result {
		t.Error("invalid proof verification returned true")
	}
	_, err = CompactProof(proof, smt.th.hasher, smt.values.GetKeySize())
	if err == nil {
		t.Error("did not return error when compacting a malformed proof")
	}

	// Case: unexpected sidenode size.
	proof, _ = smt.Prove([]byte("testKey1"))
	proof.SideNodes[0] = make([]byte, 1)
	if proof.sanityCheck(th, smt.values.GetKeySize()) {
		t.Error("sanity check incorrectly passed")
	}
	result = VerifyProof(proof, root, []byte("testKey1"), []byte("testValue1"), smt.th.hasher, smt.values.GetKeySize())
	if result {
		t.Error("invalid proof verification returned true")
	}
	_, err = CompactProof(proof, smt.th.hasher, smt.values.GetKeySize())
	if err == nil {
		t.Error("did not return error when compacting a malformed proof")
	}

	// Case: incorrect non-nil sibling data
	proof, _ = smt.ProveUpdatable([]byte("testKey1"))
	proof.SiblingData = smt.th.digest(proof.SiblingData)
	if proof.sanityCheck(th, smt.values.GetKeySize()) {
		t.Error("sanity check incorrectly passed")
	}
	result = VerifyProof(proof, root, []byte("testKey1"), []byte("testValue1"), smt.th.hasher, smt.values.GetKeySize())
	if result {
		t.Error("invalid proof verification returned true")
	}
	_, err = CompactProof(proof, smt.th.hasher, smt.values.GetKeySize())
	if err == nil {
		t.Error("did not return error when compacting a malformed proof")
	}
}

// Test sanity check cases for compact proofs.
func TestCompactProofsSanityCheck(t *testing.T) {
	hasher := sha256.New()
	smn, _ := NewSimpleMap(hasher.Size())
	smv, _ := NewSimpleMap(len([]byte("testKey1")))
	smt := NewSparseMerkleTree(smn, smv, hasher)
	th := &smt.th

	_, _ = smt.Update([]byte("testKey1"), []byte("testValue1"))
	_, _ = smt.Update([]byte("testKey2"), []byte("testValue2"))
	_, _ = smt.Update([]byte("testKey3"), []byte("testValue3"))
	root, _ := smt.Update([]byte("testKey4"), []byte("testValue4"))

	// Case (compact proofs): NumSideNodes out of range.
	proof, _ := smt.ProveCompact([]byte("testKey1"))
	proof.NumSideNodes = -1
	if proof.sanityCheck(th, smt.values.GetKeySize()) {
		t.Error("sanity check incorrectly passed")
	}
	proof.NumSideNodes = len([]byte("testKey1"))*8 + 1
	if proof.sanityCheck(th, smt.values.GetKeySize()) {
		t.Error("sanity check incorrectly passed")
	}
	result := VerifyCompactProof(proof, root, []byte("testKey1"), []byte("testValue1"), smt.th.hasher, smt.values.GetKeySize())
	if result {
		t.Error("invalid proof verification returned true")
	}

	// Case (compact proofs): unexpected bit mask length.
	proof, _ = smt.ProveCompact([]byte("testKey1"))
	proof.NumSideNodes = 10
	if proof.sanityCheck(th, smt.values.GetKeySize()) {
		t.Error("sanity check incorrectly passed")
	}
	result = VerifyCompactProof(proof, root, []byte("testKey1"), []byte("testValue1"), smt.th.hasher, smt.values.GetKeySize())
	if result {
		t.Error("invalid proof verification returned true")
	}

	// Case (compact proofs): unexpected number of sidenodes for number of side nodes.
	proof, _ = smt.ProveCompact([]byte("testKey1"))
	proof.SideNodes = append(proof.SideNodes, proof.SideNodes...)
	if proof.sanityCheck(th, smt.values.GetKeySize()) {
		t.Error("sanity check incorrectly passed")
	}
	result = VerifyCompactProof(proof, root, []byte("testKey1"), []byte("testValue1"), smt.th.hasher, smt.values.GetKeySize())
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
func checkCompactEquivalence(t *testing.T, proof SparseMerkleProof, hasher hash.Hash, keySize int) {
	compactedProof, err := CompactProof(proof, hasher, keySize)
	if err != nil {
		t.Errorf("failed to compact proof %v", err)
	}
	decompactedProof, err := DecompactProof(compactedProof, hasher, keySize)
	if err != nil {
		t.Errorf("failed to decompact proof %v", err)
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
