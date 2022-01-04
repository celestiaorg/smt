package smt

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"testing"
)

func TestDeepSubTreeKeySizeChecks(t *testing.T) {
	hasher := sha256.New()
	keySize := len([]byte("testKey1"))
	smn, smv := NewSimpleMap(hasher.Size()), NewSimpleMap(keySize)
	smt := NewSparseMerkleTree(smn, smv, hasher)

	_, err := smt.Update([]byte("testKey1"), []byte("testValue1"))
	if err != nil {
		t.Errorf("couldn't update smt. exception: %v", err)
	}

	proof, err := smt.Prove([]byte("testKey1"))
	if err != nil {
		t.Errorf("couldn't prove existing key. Actual exception: %v", err)
	}

	dsmst := NewDeepSparseMerkleSubTree(NewSimpleMap(hasher.Size()), NewSimpleMap(keySize), sha256.New(), smt.Root())

	err = dsmst.AddBranch(proof, randomBytes(keySize+1), []byte("testValue1"), smt.values.GetKeySize())
	if err != ErrWrongKeySize {
		t.Errorf("should have complained of `keySize + 1` when adding branch. Actual exception: %v", err)
	}

	err = dsmst.AddBranch(proof, randomBytes(keySize-1), []byte("testValue1"), smt.values.GetKeySize())
	if err != ErrWrongKeySize {
		t.Errorf("should have complained of `keySize - 1` when adding branch. Actual exception: %v", err)
	}

	_, err = dsmst.GetDescend(randomBytes(keySize + 1))
	if err != ErrWrongKeySize {
		t.Errorf("should have complained of `keySize + 1` when getting descend. Actual exception: %v", err)
	}

	_, err = dsmst.GetDescend(randomBytes(keySize - 1))
	if err != ErrWrongKeySize {
		t.Errorf("should have complained of `keySize - 1` when getting descend. Actual exception: %v", err)
	}
}

func TestDeepSparseMerkleSubTreeBasic(t *testing.T) {
	hasher := sha256.New()
	smt := NewSparseMerkleTree(NewSimpleMap(hasher.Size()), NewSimpleMap(len([]byte("testKey1"))), hasher)

	_, _ = smt.Update([]byte("testKey1"), []byte("testValue1"))
	_, _ = smt.Update([]byte("testKey2"), []byte("testValue2"))
	_, _ = smt.Update([]byte("testKey3"), []byte("testValue3"))
	_, _ = smt.Update([]byte("testKey4"), []byte("testValue4"))
	_, _ = smt.Update([]byte("testKey6"), []byte("testValue6"))

	originalRoot := make([]byte, len(smt.Root()))
	copy(originalRoot, smt.Root())

	proof1, _ := smt.ProveUpdatable([]byte("testKey1"))
	proof2, _ := smt.ProveUpdatable([]byte("testKey2"))
	proof5, _ := smt.ProveUpdatable([]byte("testKey5"))

	dsmst := NewDeepSparseMerkleSubTree(NewSimpleMap(hasher.Size()), NewSimpleMap(len([]byte("testKey1"))), sha256.New(), smt.Root())
	err := dsmst.AddBranch(proof1, []byte("testKey1"), []byte("testValue1"), smt.values.GetKeySize())
	if err != nil {
		t.Errorf("returned error when adding branch to deep subtree: %v", err)
	}
	err = dsmst.AddBranch(proof2, []byte("testKey2"), []byte("testValue2"), smt.values.GetKeySize())
	if err != nil {
		t.Errorf("returned error when adding branch to deep subtree: %v", err)
	}
	err = dsmst.AddBranch(proof5, []byte("testKey5"), defaultValue, smt.values.GetKeySize())
	if err != nil {
		t.Errorf("returned error when adding branch to deep subtree: %v", err)
	}

	value, err := dsmst.Get([]byte("testKey1"))
	if err != nil {
		t.Errorf("returned error when getting value in deep subtree: %v", err)
	}
	if !bytes.Equal(value, []byte("testValue1")) {
		t.Error("did not get correct value in deep subtree")
	}
	value, err = dsmst.GetDescend([]byte("testKey1"))
	if err != nil {
		t.Errorf("returned error when getting value in deep subtree: %v", err)
	}
	if !bytes.Equal(value, []byte("testValue1")) {
		t.Error("did not get correct value in deep subtree")
	}
	value, err = dsmst.Get([]byte("testKey2"))
	if err != nil {
		t.Errorf("returned error when getting value in deep subtree: %v", err)
	}
	if !bytes.Equal(value, []byte("testValue2")) {
		t.Error("did not get correct value in deep subtree")
	}
	value, err = dsmst.GetDescend([]byte("testKey2"))
	if err != nil {
		t.Errorf("returned error when getting value in deep subtree: %v", err)
	}
	if !bytes.Equal(value, []byte("testValue2")) {
		t.Error("did not get correct value in deep subtree")
	}
	value, err = dsmst.Get([]byte("testKey5"))
	if err != nil {
		t.Errorf("returned error when getting value in deep subtree: %v", err)
	}
	if !bytes.Equal(value, defaultValue) {
		t.Error("did not get correct value in deep subtree")
	}
	value, err = dsmst.GetDescend([]byte("testKey5"))
	if err != nil {
		t.Errorf("returned error when getting value in deep subtree: %v", err)
	}
	if !bytes.Equal(value, defaultValue) {
		t.Error("did not get correct value in deep subtree")
	}
	_, err = dsmst.GetDescend([]byte("testKey6"))
	if err == nil {
		t.Error("did not error when getting non-added value in deep subtree")
	}

	_, err = dsmst.Update([]byte("testKey1"), []byte("testValue3"))
	if err != nil {
		t.Errorf("returned error when updating deep subtree: %v", err)
	}
	_, err = dsmst.Update([]byte("testKey2"), defaultValue)
	if err != nil {
		t.Errorf("returned error when updating deep subtree: %v", err)
	}
	_, err = dsmst.Update([]byte("testKey5"), []byte("testValue5"))
	if err != nil {
		t.Errorf("returned error when updating deep subtree: %v", err)
	}

	value, err = dsmst.Get([]byte("testKey1"))
	if err != nil {
		t.Error("returned error when getting value in deep subtree")
	}
	if !bytes.Equal(value, []byte("testValue3")) {
		t.Error("did not get correct value in deep subtree")
	}
	value, err = dsmst.Get([]byte("testKey2"))
	if err != nil {
		t.Error("returned error when getting value in deep subtree")
	}
	if !bytes.Equal(value, defaultValue) {
		t.Error("did not get correct value in deep subtree")
	}
	value, err = dsmst.Get([]byte("testKey5"))
	if err != nil {
		t.Error("returned error when getting value in deep subtree")
	}
	if !bytes.Equal(value, []byte("testValue5")) {
		t.Error("did not get correct value in deep subtree")
	}

	_, err = smt.Update([]byte("testKey1"), []byte("testValue3"))
	if err != nil {
		t.Errorf("returned error when updating main tree: %v", err)
	}
	_, err = smt.Update([]byte("testKey2"), defaultValue)
	if err != nil {
		t.Errorf("returned error when updating main tree: %v", err)
	}
	_, err = smt.Update([]byte("testKey5"), []byte("testValue5"))
	if err != nil {
		t.Errorf("returned error when updating main tree: %v", err)
	}

	if !bytes.Equal(smt.Root(), dsmst.Root()) {
		t.Error("roots of identical standard tree and subtree do not match")
	}
	if bytes.Equal(smt.Root(), originalRoot) {
		t.Error("root stayed the same despite updates")
	}
}

func TestDeepSparseMerkleSubTreeBadInput(t *testing.T) {
	hasher := sha256.New()
	smt := NewSparseMerkleTree(NewSimpleMap(hasher.Size()), NewSimpleMap(len([]byte("testKey1"))), hasher) // to be refactored

	_, _ = smt.Update([]byte("testKey1"), []byte("testValue1"))
	_, _ = smt.Update([]byte("testKey2"), []byte("testValue2"))
	_, _ = smt.Update([]byte("testKey3"), []byte("testValue3"))
	_, _ = smt.Update([]byte("testKey4"), []byte("testValue4"))

	badProof, _ := smt.Prove([]byte("testKey1"))
	badProof.SideNodes[0][0] = byte(0)

	dsmst := NewDeepSparseMerkleSubTree(NewSimpleMap(hasher.Size()), NewSimpleMap(len([]byte("testKey1"))), hasher, smt.Root()) // to be refactored
	err := dsmst.AddBranch(badProof, []byte("testKey1"), []byte("testValue1"), smt.values.GetKeySize())
	if !errors.Is(err, ErrBadProof) {
		t.Error("did not return ErrBadProof for bad proof input")
	}
}
