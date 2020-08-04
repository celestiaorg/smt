package smt

import (
	"crypto/sha256"
	"math/rand"
	"reflect"
	"testing"
	"hash"
	"bytes"
)

type testUpdater func(key []byte, value []byte) ([]byte, error)
type testProver func(key []byte) (SparseMerkleProof, error)
type testVerifier func(proof SparseMerkleProof, root []byte, key []byte, value []byte, hasher hash.Hash) bool

// Test base case Merkle proof operations.
func TestProofsBasic(t *testing.T) {
	var sm *SimpleMap
	var smt *SparseMerkleTree

	sm = NewSimpleMap()
	smt = NewSparseMerkleTree(sm, sha256.New())
	testProofsBasic(t, smt.Update, smt.Prove, VerifyProof)
	
	sm = NewSimpleMap()
	smt = NewSparseMerkleTree(sm, sha256.New())
	testProofsBasic(t, smt.Update, smt.ProveCompact, VerifyCompactProof)
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

	t.Log(proof)

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
	proof, err = prove([]byte("testKey2"))
	if err != nil {
		t.Error("error returned when trying to prove inclusion")
		t.Log(err)
	}
	result = verify(proof, root, []byte("testKey2"), []byte("testValue"), sha256.New())
	if !result {
		t.Error("valid proof failed to verify")
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
}

func TestProofsOld(t *testing.T) {
	sm := NewSimpleMap()
	smt := NewSparseMerkleTree(sm, sha256.New())
	var err error

	badSideNodes := make([][]byte, smt.depth())
	for i := 0; i < len(badSideNodes); i++ {
		badSideNodes[i] = make([]byte, smt.depth())
		rand.Read(badSideNodes[i])
	}
	badProof := SparseMerkleProof{SideNodes: badSideNodes}

	smt.Update([]byte("testKey"), []byte("testValue"))

	proof, err := smt.Prove([]byte("testKey"))
	if err != nil {
		t.Error("error returned when trying to prove inclusion")
	}
	result := VerifyProof(proof, smt.root, []byte("testKey"), []byte("testValue"), sha256.New())
	if !result {
		t.Error("valid proof failed to verify")
	}
	result = VerifyProof(proof, smt.root, []byte("testKey"), []byte("badValue"), sha256.New())
	if result {
		t.Error("invalid proof verification returned true")
	}
	result = VerifyProof(proof, smt.root, []byte("testKey1"), []byte("testValue"), sha256.New())
	if result {
		t.Error("invalid proof verification returned true")
	}
	result = VerifyProof(badProof, smt.root, []byte("testKey"), []byte("testValue"), sha256.New())
	if result {
		t.Error("invalid proof verification returned true")
	}

	smt.Update([]byte("testKey2"), []byte("testValue"))

	proof, err = smt.Prove([]byte("testKey"))
	if err != nil {
		t.Error("error returned when trying to prove inclusion")
	}
	result = VerifyProof(proof, smt.root, []byte("testKey"), []byte("testValue"), sha256.New())
	if !result {
		t.Error("valid proof failed to verify")
	}
	result = VerifyProof(proof, smt.root, []byte("testKey"), []byte("badValue"), sha256.New())
	if result {
		t.Error("invalid proof verification returned true")
	}
	result = VerifyProof(proof, smt.root, []byte("testKey2"), []byte("testValue"), sha256.New())
	if result {
		t.Error("invalid proof verification returned true")
	}
	result = VerifyProof(badProof, smt.root, []byte("testKey"), []byte("testValue"), sha256.New())
	if result {
		t.Error("invalid proof verification returned true")
	}

	proof, err = smt.Prove([]byte("testKey2"))
	if err != nil {
		t.Error("error returned when trying to prove inclusion")
		t.Log(err)
	}
	result = VerifyProof(proof, smt.root, []byte("testKey2"), []byte("testValue"), sha256.New())
	if !result {
		t.Error("valid proof failed to verify")
	}
	result = VerifyProof(proof, smt.root, []byte("testKey2"), []byte("badValue"), sha256.New())
	if result {
		t.Error("invalid proof verification returned true")
	}
	result = VerifyProof(proof, smt.root, []byte("testKey3"), []byte("testValue"), sha256.New())
	if result {
		t.Error("invalid proof verification returned true")
	}
	result = VerifyProof(badProof, smt.root, []byte("testKey"), []byte("testValue"), sha256.New())
	if result {
		t.Error("invalid proof verification returned true")
	}

	proof, err = smt.Prove([]byte("testKey3"))
	if err != nil {
		t.Error("error returned when trying to prove inclusion on empty key")
	}
	result = VerifyProof(proof, smt.root, []byte("testKey3"), defaultValue, sha256.New())
	if !result {
		t.Error("valid proof on empty key failed to verify")
	}
	result = VerifyProof(proof, smt.root, []byte("testKey3"), []byte("badValue"), sha256.New())
	if result {
		t.Error("invalid proof verification on empty key returned true")
	}
	result = VerifyProof(proof, smt.root, []byte("testKey2"), defaultValue, sha256.New())
	if result {
		t.Error("invalid proof verification on empty key returned true")
	}
	result = VerifyProof(badProof, smt.root, []byte("testKey"), []byte("testValue"), sha256.New())
	if result {
		t.Error("invalid proof verification on empty key returned true")
	}

	compactProof, err := CompactProof(proof, sha256.New())
	decompactedProof, err := DecompactProof(compactProof, sha256.New())
	if !reflect.DeepEqual(proof, decompactedProof) {
		t.Error("compacting and decompacting proof returns a different proof than the original proof")
	}

	badSideNodes2 := make([][]byte, sha256.New().Size()*8+1)
	for i := 0; i < len(badSideNodes2); i++ {
		badSideNodes2[i] = make([]byte, sha256.New().Size())
		rand.Read(badSideNodes2[i])
	}
	badProof2 := SparseMerkleProof{SideNodes: badSideNodes2}

	badSideNodes3 := make([][]byte, sha256.New().Size()*8-1)
	for i := 0; i < len(badSideNodes3); i++ {
		badSideNodes3[i] = make([]byte, sha256.New().Size())
		rand.Read(badSideNodes3[i])
	}
	badProof3 := SparseMerkleProof{SideNodes: badSideNodes3}

	badSideNodes4 := make([][]byte, sha256.New().Size()*8)
	for i := 0; i < len(badSideNodes4); i++ {
		badSideNodes4[i] = make([]byte, sha256.New().Size()-1)
		rand.Read(badSideNodes4[i])
	}
	badProof4 := SparseMerkleProof{SideNodes: badSideNodes4}

	badSideNodes5 := make([][]byte, sha256.New().Size()*8)
	for i := 0; i < len(badSideNodes5); i++ {
		badSideNodes5[i] = make([]byte, sha256.New().Size()+1)
		rand.Read(badSideNodes5[i])
	}
	badProof5 := SparseMerkleProof{SideNodes: badSideNodes5}

	badSideNodes6 := make([][]byte, sha256.New().Size()*8)
	for i := 0; i < len(badSideNodes6); i++ {
		badSideNodes6[i] = make([]byte, 1)
		rand.Read(badSideNodes6[i])
	}
	badProof6 := SparseMerkleProof{SideNodes: badSideNodes6}

	result = VerifyProof(badProof2, smt.root, []byte("testKey3"), defaultValue, sha256.New())
	if result {
		t.Error("invalid proof verification returned true")
	}
	result = VerifyProof(badProof3, smt.root, []byte("testKey3"), defaultValue, sha256.New())
	if result {
		t.Error("invalid proof verification returned true")
	}
	result = VerifyProof(badProof4, smt.root, []byte("testKey3"), defaultValue, sha256.New())
	if result {
		t.Error("invalid proof verification returned true")
	}
	result = VerifyProof(badProof5, smt.root, []byte("testKey3"), defaultValue, sha256.New())
	if result {
		t.Error("invalid proof verification returned true")
	}
	result = VerifyProof(badProof6, smt.root, []byte("testKey3"), defaultValue, sha256.New())
	if result {
		t.Error("invalid proof verification returned true")
	}

	compactProof, err = CompactProof(badProof2, sha256.New())
	if err == nil {
		t.Error("CompactProof did not return error on bad proof size")
	}

	proof, err = smt.ProveCompact([]byte("testKey2"))
	if err != nil {
		t.Error("error returned when trying to prove inclusion")
		t.Log(err)
	}
	result = VerifyCompactProof(proof, smt.root, []byte("testKey2"), []byte("testValue"), sha256.New())
	if !result {
		t.Error("valid proof failed to verify")
	}
	result = VerifyCompactProof(proof, smt.root, []byte("testKey2"), []byte("badValue"), sha256.New())
	if result {
		t.Error("invalid proof verification returned true")
	}
	result = VerifyCompactProof(proof, smt.root, []byte("testKey3"), []byte("testValue"), sha256.New())
	if result {
		t.Error("invalid proof verification returned true")
	}
	result = VerifyCompactProof(badProof, smt.root, []byte("testKey"), []byte("testValue"), sha256.New())
	if result {
		t.Error("invalid proof verification returned true")
	}

	root := smt.Root()
	smt.Update([]byte("testKey2"), []byte("testValue2"))

	proof, err = smt.ProveCompactForRoot([]byte("testKey2"), root)
	if err != nil {
		t.Error("error returned when trying to prove inclusion")
		t.Log(err)
	}
	result = VerifyCompactProof(proof, root, []byte("testKey2"), []byte("testValue"), sha256.New())
	if !result {
		t.Error("valid proof failed to verify")
	}
	result = VerifyCompactProof(proof, root, []byte("testKey2"), []byte("badValue"), sha256.New())
	if result {
		t.Error("invalid proof verification returned true")
	}
	result = VerifyCompactProof(proof, root, []byte("testKey3"), []byte("testValue"), sha256.New())
	if result {
		t.Error("invalid proof verification returned true")
	}
	result = VerifyCompactProof(badProof, root, []byte("testKey"), []byte("testValue"), sha256.New())
	if result {
		t.Error("invalid proof verification returned true")
	}

	proof, err = smt.ProveForRoot([]byte("testKey2"), root)
	if err != nil {
		t.Error("error returned when trying to prove inclusion")
		t.Log(err)
	}
	result = VerifyProof(proof, root, []byte("testKey2"), []byte("testValue"), sha256.New())
	if !result {
		t.Error("valid proof failed to verify")
	}
	result = VerifyProof(proof, root, []byte("testKey2"), []byte("badValue"), sha256.New())
	if result {
		t.Error("invalid proof verification returned true")
	}
	result = VerifyProof(proof, root, []byte("testKey3"), []byte("testValue"), sha256.New())
	if result {
		t.Error("invalid proof verification returned true")
	}
	result = VerifyProof(badProof, root, []byte("testKey"), []byte("testValue"), sha256.New())
	if result {
		t.Error("invalid proof verification returned true")
	}
}
