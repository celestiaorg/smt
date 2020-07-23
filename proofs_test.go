package smt

import (
	"crypto/sha256"
	"math/rand"
	//"reflect"
	"testing"
)

func TestProofs(t *testing.T) {
	sm := NewSimpleMap()
	smt := NewSparseMerkleTree(sm, sha256.New())
	var err error

	badSideNodes := make([][]byte, smt.depth())
	for i := 0; i < len(badSideNodes); i++ {
		badSideNodes[i] = make([]byte, smt.depth())
		rand.Read(badSideNodes[i])
	}
	badProof := SparseMerkleProof{badSideNodes, nil}

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
		t.Log(err)
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

	/*compactProof, err := CompactProof(proof, sha256.New())
	decompactedProof, err := DecompactProof(compactProof, sha256.New())
	if !reflect.DeepEqual(proof, decompactedProof) {
		t.Error("compacting and decompacting proof returns a different proof than the original proof")
	}

	badProof2 := make([][]byte, sha256.New().Size()*8+1)
	for i := 0; i < len(badProof); i++ {
		badProof[i] = make([]byte, sha256.New().Size())
		rand.Read(badProof[i])
	}
	badProof3 := make([][]byte, sha256.New().Size()*8-1)
	for i := 0; i < len(badProof); i++ {
		badProof[i] = make([]byte, sha256.New().Size())
		rand.Read(badProof[i])
	}
	badProof4 := make([][]byte, sha256.New().Size()*8)
	for i := 0; i < len(badProof); i++ {
		badProof[i] = make([]byte, sha256.New().Size()-1)
		rand.Read(badProof[i])
	}
	badProof5 := make([][]byte, sha256.New().Size()*8)
	for i := 0; i < len(badProof); i++ {
		badProof[i] = make([]byte, sha256.New().Size()+1)
		rand.Read(badProof[i])
	}
	badProof6 := make([][]byte, sha256.New().Size()*8)
	for i := 0; i < len(badProof); i++ {
		badProof[i] = make([]byte, 1)
		rand.Read(badProof[i])
	}

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
	compactProof, err = CompactProof(badProof3, sha256.New())
	if err == nil {
		t.Error("CompactProof did not return error on bad proof size")
	}

	decompactedProof, err = DecompactProof(badProof3, sha256.New())
	if err == nil {
		t.Error("DecompactProof did not return error on bad proof size")
	}
	decompactedProof, err = DecompactProof([][]byte{}, sha256.New())
	if err == nil {
		t.Error("DecompactProof did not return error on bad proof size")
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
	}*/
}
