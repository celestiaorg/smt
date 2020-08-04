package smt

import (
	"crypto/sha256"
	"testing"
	"hash"
	"bytes"
	"math/rand"
)

type testUpdater func(key []byte, value []byte) ([]byte, error)
type testProver func(key []byte) (SparseMerkleProof, error)
type testVerifier func(proof SparseMerkleProof, root []byte, key []byte, value []byte, hasher hash.Hash) bool

// Test base case Merkle proof operations.
func TestProofsBasic(t *testing.T) {
	var sm *SimpleMap
	var smt *SparseMerkleTree

	// Test non-compact proofs.
	sm = NewSimpleMap()
	smt = NewSparseMerkleTree(sm, sha256.New())
	testProofsBasic(t, smt.Update, smt.Prove, VerifyProof)

	// Test compact proofs.
	sm = NewSimpleMap()
	smt = NewSparseMerkleTree(sm, sha256.New())
	testProofsBasic(t, smt.Update, smt.ProveCompact, VerifyCompactProof)
}

// Test sanity check cases.
func TestProofsSanityCheck(t *testing.T) {
	sm := NewSimpleMap()
	smt := NewSparseMerkleTree(sm, sha256.New())
	th := &smt.th

	smt.Update([]byte("testKey1"), []byte("testValue1"))
	smt.Update([]byte("testKey2"), []byte("testValue2"))
	smt.Update([]byte("testKey3"), []byte("testValue3"))
	smt.Update([]byte("testKey4"), []byte("testValue4"))

	// Case: invalid number of sidenodes.
	proof, _ := smt.Prove([]byte("testKey1"))
	sideNodes := make([][]byte, smt.th.pathSize()*8+1)
	for i, _ := range sideNodes {
		sideNodes[i] = proof.SideNodes[0]
	}
	proof.SideNodes = sideNodes
	if proof.sanityCheck(th) {
		t.Error("sanity check incorrectly passed")
	}

	// Case: incorrect size for NonMembershipLeafData.
	proof, _ = smt.Prove([]byte("testKey1"))
	proof.NonMembershipLeafData = make([]byte, 1)
	if proof.sanityCheck(th) {
		t.Error("sanity check incorrectly passed")
	}

	// Case: NumSideNodes out of range.
	proof, _ = smt.Prove([]byte("testKey1"))
	proof.NumSideNodes = -1
	if proof.sanityCheck(th) {
		t.Error("sanity check incorrectly passed")
	}
	proof.NumSideNodes = th.pathSize()*8+1
	if proof.sanityCheck(th) {
		t.Error("sanity check incorrectly passed")
	}

	// Case: unexpected bit mask length.
	proof, _ = smt.Prove([]byte("testKey1"))
	proof.NumSideNodes = 1
	if proof.sanityCheck(th) {
		t.Error("sanity check incorrectly passed")
	}

	// Case: unexpected number of sidenodes for number of side nodes.
	proof, _ = smt.ProveCompact([]byte("testKey1"))
	proof.SideNodes = proof.SideNodes[:1]
	if proof.sanityCheck(th) {
		t.Error("sanity check incorrectly passed")
	}

	// Case: unexpected sidenode size.
	proof, _ = smt.Prove([]byte("testKey1"))
	proof.SideNodes[0] = make([]byte, 1)
	if proof.sanityCheck(th) {
		t.Error("sanity check incorrectly passed")
	}
}

func testProofsBasic(t *testing.T, update testUpdater, prove testProver, verify testVerifier) {
	var proof SparseMerkleProof
	var result bool
	var root []byte
	var err error

	// Generate and verify a proof on an empty key.
	proof, err = prove([]byte("testKey3"))
	if err != nil {
		t.Error("error returned when trying to prove inclusion on empty key")
	}
	result = verify(proof, bytes.Repeat([]byte{0}, sha256.New().Size()), []byte("testKey3"), defaultValue, sha256.New())
	if !result {
		t.Error("valid proof on empty key failed to verify")
	}
	result = verify(proof, root, []byte("testKey3"), []byte("badValue"), sha256.New())
	if result {
		t.Error("invalid proof verification returned true")
	}

	// Add a key, generate and verify a Merkle proof.
	root, _ = update([]byte("testKey"), []byte("testValue"))
	proof, err = prove([]byte("testKey"))
	if err != nil {
		t.Error("error returned when trying to prove inclusion")
	}
	result = verify(proof, root, []byte("testKey"), []byte("testValue"), sha256.New())
	if !result {
		t.Error("valid proof failed to verify")
	}
	result = verify(proof, root, []byte("testKey"), []byte("badValue"), sha256.New())
	if result {
		t.Error("invalid proof verification returned true")
	}

	// Add a key, generate and verify both Merkle proofs.
	root, _ = update([]byte("testKey2"), []byte("testValue"))
	proof, err = prove([]byte("testKey"))
	if err != nil {
		t.Error("error returned when trying to prove inclusion")
	}
	result = verify(proof, root, []byte("testKey"), []byte("testValue"), sha256.New())
	if !result {
		t.Error("valid proof failed to verify")
	}
	result = verify(proof, root, []byte("testKey"), []byte("badValue"), sha256.New())
	if result {
		t.Error("invalid proof verification returned true")
	}
	result = verify(randomiseProof(proof), root, []byte("testKey"), []byte("testValue"), sha256.New())
	if result {
		t.Error("invalid proof verification returned true")
	}

	proof, err = prove([]byte("testKey2"))
	if err != nil {
		t.Error("error returned when trying to prove inclusion")
	}
	result = verify(proof, root, []byte("testKey2"), []byte("testValue"), sha256.New())
	if !result {
		t.Error("valid proof failed to verify")
	}
	result = verify(proof, root, []byte("testKey2"), []byte("badValue"), sha256.New())
	if result {
		t.Error("invalid proof verification returned true")
	}
	result = verify(randomiseProof(proof), root, []byte("testKey2"), []byte("testValue"), sha256.New())
	if result {
		t.Error("invalid proof verification returned true")
	}

	// Generate and verify a proof on an empty key.
	proof, err = prove([]byte("testKey3"))
	if err != nil {
		t.Error("error returned when trying to prove inclusion on empty key")
	}
	result = verify(proof, root, []byte("testKey3"), defaultValue, sha256.New())
	if !result {
		t.Error("valid proof on empty key failed to verify")
	}
	result = verify(proof, root, []byte("testKey3"), []byte("badValue"), sha256.New())
	if result {
		t.Error("invalid proof verification returned true")
	}
	result = verify(randomiseProof(proof), root, []byte("testKey3"), defaultValue, sha256.New())
	if result {
		t.Error("invalid proof verification returned true")
	}
}

func randomiseProof(proof SparseMerkleProof) SparseMerkleProof {
	sideNodes := make([][]byte, len(proof.SideNodes))
	for i, _ := range sideNodes {
		sideNodes[i] = make([]byte, len(proof.SideNodes[i]))
		rand.Read(sideNodes[i])
	}
	return SparseMerkleProof{
		SideNodes: sideNodes,
		NonMembershipLeafData: proof.NonMembershipLeafData,
		BitMask: proof.BitMask,
		NumSideNodes: proof.NumSideNodes,
	}
}
