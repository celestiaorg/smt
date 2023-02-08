package smt

import (
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/require"
)

// Test base case Merkle proof operations.
func TestProofsBasic(t *testing.T) {
	var smn, smv *SimpleMap
	var smt *SMTWithStorage
	var proof SparseMerkleProof
	var result bool
	var root []byte
	var err error

	smn, smv = NewSimpleMap(), NewSimpleMap()
	smt = NewSMTWithStorage(smn, smv, sha256.New())
	base := smt.Spec()

	// Generate and verify a proof on an empty key.
	proof, err = smt.Prove([]byte("testKey3"))
	require.NoError(t, err)
	checkCompactEquivalence(t, proof, base)
	result = VerifyProof(proof, base.th.placeholder(), []byte("testKey3"), defaultValue, base)
	require.True(t, result)
	result = VerifyProof(proof, root, []byte("testKey3"), []byte("badValue"), base)
	require.False(t, result)

	// Add a key, generate and verify a Merkle proof.
	err = smt.Update([]byte("testKey"), []byte("testValue"))
	require.NoError(t, err)
	root = smt.Root()
	proof, err = smt.Prove([]byte("testKey"))
	require.NoError(t, err)
	checkCompactEquivalence(t, proof, base)
	result = VerifyProof(proof, root, []byte("testKey"), []byte("testValue"), base)
	require.True(t, result)
	result = VerifyProof(proof, root, []byte("testKey"), []byte("badValue"), base)
	require.False(t, result)

	// Add a key, generate and verify both Merkle proofs.
	err = smt.Update([]byte("testKey2"), []byte("testValue"))
	require.NoError(t, err)
	root = smt.Root()
	proof, err = smt.Prove([]byte("testKey"))
	require.NoError(t, err)
	checkCompactEquivalence(t, proof, base)
	result = VerifyProof(proof, root, []byte("testKey"), []byte("testValue"), base)
	require.True(t, result)
	result = VerifyProof(proof, root, []byte("testKey"), []byte("badValue"), base)
	require.False(t, result)
	result = VerifyProof(randomiseProof(proof), root, []byte("testKey"), []byte("testValue"), base)
	require.False(t, result)

	proof, err = smt.Prove([]byte("testKey2"))
	require.NoError(t, err)
	checkCompactEquivalence(t, proof, base)
	result = VerifyProof(proof, root, []byte("testKey2"), []byte("testValue"), base)
	require.True(t, result)
	result = VerifyProof(proof, root, []byte("testKey2"), []byte("badValue"), base)
	require.False(t, result)
	result = VerifyProof(randomiseProof(proof), root, []byte("testKey2"), []byte("testValue"), base)
	require.False(t, result)

	// Try proving a default value for a non-default leaf.
	_, leafData := base.th.digestLeaf(base.ph.Path([]byte("testKey2")), base.digestValue([]byte("testValue")))
	proof = SparseMerkleProof{
		SideNodes:             proof.SideNodes,
		NonMembershipLeafData: leafData,
	}
	result = VerifyProof(proof, root, []byte("testKey2"), defaultValue, base)
	require.False(t, result)

	// Generate and verify a proof on an empty key.
	proof, err = smt.Prove([]byte("testKey3"))
	require.NoError(t, err)
	checkCompactEquivalence(t, proof, base)
	result = VerifyProof(proof, root, []byte("testKey3"), defaultValue, base)
	require.True(t, result)
	result = VerifyProof(proof, root, []byte("testKey3"), []byte("badValue"), base)
	require.False(t, result)
	result = VerifyProof(randomiseProof(proof), root, []byte("testKey3"), defaultValue, base)
	require.False(t, result)
}

// Test sanity check cases for non-compact proofs.
func TestProofsSanityCheck(t *testing.T) {
	smn, smv := NewSimpleMap(), NewSimpleMap()
	smt := NewSMTWithStorage(smn, smv, sha256.New())
	base := smt.Spec()

	smt.Update([]byte("testKey1"), []byte("testValue1"))
	smt.Update([]byte("testKey2"), []byte("testValue2"))
	smt.Update([]byte("testKey3"), []byte("testValue3"))
	smt.Update([]byte("testKey4"), []byte("testValue4"))
	root := smt.Root()

	// Case: invalid number of sidenodes.
	proof, _ := smt.Prove([]byte("testKey1"))
	sideNodes := make([][]byte, smt.Spec().depth()+1)
	for i := range sideNodes {
		sideNodes[i] = proof.SideNodes[0]
	}
	proof.SideNodes = sideNodes
	require.False(t, proof.sanityCheck(base))
	result := VerifyProof(proof, root, []byte("testKey1"), []byte("testValue1"), base)
	require.False(t, result)
	_, err := CompactProof(proof, base)
	require.Error(t, err)

	// Case: incorrect size for NonMembershipLeafData.
	proof, _ = smt.Prove([]byte("testKey1"))
	proof.NonMembershipLeafData = make([]byte, 1)
	require.False(t, proof.sanityCheck(base))
	result = VerifyProof(proof, root, []byte("testKey1"), []byte("testValue1"), base)
	require.False(t, result)
	_, err = CompactProof(proof, base)
	require.Error(t, err)

	// Case: unexpected sidenode size.
	proof, _ = smt.Prove([]byte("testKey1"))
	proof.SideNodes[0] = make([]byte, 1)
	require.False(t, proof.sanityCheck(base))
	result = VerifyProof(proof, root, []byte("testKey1"), []byte("testValue1"), base)
	require.False(t, result)
	_, err = CompactProof(proof, base)
	require.Error(t, err)

	// Case: incorrect non-nil sibling data
	proof, _ = smt.Prove([]byte("testKey1"))
	proof.SiblingData = base.th.digest(proof.SiblingData)
	require.False(t, proof.sanityCheck(base))

	result = VerifyProof(proof, root, []byte("testKey1"), []byte("testValue1"), base)
	require.False(t, result)
	_, err = CompactProof(proof, base)
	require.Error(t, err)
}
