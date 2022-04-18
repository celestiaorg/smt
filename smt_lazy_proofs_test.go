package smt

import (
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/require"
)

// Test base case Merkle proof operations.
func TestLazyProofsBasic(t *testing.T) {
	var smn, smv *SimpleMap
	var smt *SMTWithStorage
	var proof SparseMerkleProof
	var result bool
	var root []byte
	var err error

	smn, smv = NewSimpleMap(), NewSimpleMap()
	smt = NewLazySMTWithStorage(smn, smv, sha256.New())
	th := smt.base().th

	// Generate and verify a proof on an empty key.
	proof, err = smt.Prove([]byte("testKey3"))
	require.NoError(t, err)
	checkCompactEquivalence(t, proof, th)
	result = VerifyProof(proof, th.placeholder(), []byte("testKey3"), defaultValue, th)
	require.True(t, result)
	result = VerifyProof(proof, root, []byte("testKey3"), []byte("badValue"), th)
	require.False(t, result)

	// Add a key, generate and verify a Merkle proof.
	err = smt.Update([]byte("testKey"), []byte("testValue"))
	require.NoError(t, err)
	root = smt.Root()
	proof, err = smt.Prove([]byte("testKey"))
	require.NoError(t, err)
	checkCompactEquivalence(t, proof, th)
	result = VerifyProof(proof, root, []byte("testKey"), []byte("testValue"), th)
	require.True(t, result)
	result = VerifyProof(proof, root, []byte("testKey"), []byte("badValue"), th)
	require.False(t, result)

	// Add a key, generate and verify both Merkle proofs.
	err = smt.Update([]byte("testKey2"), []byte("testValue"))
	require.NoError(t, err)
	root = smt.Root()
	proof, err = smt.Prove([]byte("testKey"))
	require.NoError(t, err)
	checkCompactEquivalence(t, proof, th)
	result = VerifyProof(proof, root, []byte("testKey"), []byte("testValue"), th)
	require.True(t, result)
	result = VerifyProof(proof, root, []byte("testKey"), []byte("badValue"), th)
	require.False(t, result)
	result = VerifyProof(randomiseProof(proof), root, []byte("testKey"), []byte("testValue"), th)
	require.False(t, result)

	proof, err = smt.Prove([]byte("testKey2"))
	require.NoError(t, err)
	checkCompactEquivalence(t, proof, th)
	result = VerifyProof(proof, root, []byte("testKey2"), []byte("testValue"), th)
	require.True(t, result)
	result = VerifyProof(proof, root, []byte("testKey2"), []byte("badValue"), th)
	require.False(t, result)
	result = VerifyProof(randomiseProof(proof), root, []byte("testKey2"), []byte("testValue"), th)
	require.False(t, result)

	// Try proving a default value for a non-default leaf.
	_, leafData := th.digestLeaf(th.Path([]byte("testKey2")), th.digest([]byte("testValue")))
	proof = SparseMerkleProof{
		SideNodes:             proof.SideNodes,
		NonMembershipLeafData: leafData,
	}
	result = VerifyProof(proof, root, []byte("testKey2"), defaultValue, th)
	require.False(t, result)

	// Generate and verify a proof on an empty key.
	proof, err = smt.Prove([]byte("testKey3"))
	require.NoError(t, err)
	checkCompactEquivalence(t, proof, th)
	result = VerifyProof(proof, root, []byte("testKey3"), defaultValue, th)
	require.True(t, result)
	result = VerifyProof(proof, root, []byte("testKey3"), []byte("badValue"), th)
	require.False(t, result)
	result = VerifyProof(randomiseProof(proof), root, []byte("testKey3"), defaultValue, th)
	require.False(t, result)
}

// Test sanity check cases for non-compact proofs.
func TestLazyProofsSanityCheck(t *testing.T) {
	smn, smv := NewSimpleMap(), NewSimpleMap()
	smt := NewLazySMTWithStorage(smn, smv, sha256.New())
	th := smt.base().th

	smt.Update([]byte("testKey1"), []byte("testValue1"))
	smt.Update([]byte("testKey2"), []byte("testValue2"))
	smt.Update([]byte("testKey3"), []byte("testValue3"))
	smt.Update([]byte("testKey4"), []byte("testValue4"))
	root := smt.Root()

	// Case: invalid number of sidenodes.
	proof, _ := smt.Prove([]byte("testKey1"))
	sideNodes := make([][]byte, smt.base().depth()+1)
	for i := range sideNodes {
		sideNodes[i] = proof.SideNodes[0]
	}
	proof.SideNodes = sideNodes
	require.False(t, proof.sanityCheck(th))
	result := VerifyProof(proof, root, []byte("testKey1"), []byte("testValue1"), th)
	require.False(t, result)
	_, err := CompactProof(proof, th)
	require.Error(t, err)

	// Case: incorrect size for NonMembershipLeafData.
	proof, _ = smt.Prove([]byte("testKey1"))
	proof.NonMembershipLeafData = make([]byte, 1)
	require.False(t, proof.sanityCheck(th))
	result = VerifyProof(proof, root, []byte("testKey1"), []byte("testValue1"), th)
	require.False(t, result)
	_, err = CompactProof(proof, th)
	require.Error(t, err)

	// Case: unexpected sidenode size.
	proof, _ = smt.Prove([]byte("testKey1"))
	proof.SideNodes[0] = make([]byte, 1)
	require.False(t, proof.sanityCheck(th))
	result = VerifyProof(proof, root, []byte("testKey1"), []byte("testValue1"), th)
	require.False(t, result)
	_, err = CompactProof(proof, th)
	require.Error(t, err)

	// Case: incorrect non-nil sibling data
	proof, _ = smt.Prove([]byte("testKey1"))
	proof.SiblingData = th.digest(proof.SiblingData)
	require.False(t, proof.sanityCheck(th))

	result = VerifyProof(proof, root, []byte("testKey1"), []byte("testValue1"), th)
	require.False(t, result)
	_, err = CompactProof(proof, th)
	require.Error(t, err)
}
