package smt

import (
	"bytes"
	"crypto/sha256"
	"testing"
)

func TestDeepSparseMerkleSubTreeBasic(t *testing.T) {
	smt := NewSparseMerkleTree(NewSimpleMap(), sha256.New())

	smt.Update([]byte("testKey1"), []byte("testValue1"))
	smt.Update([]byte("testKey2"), []byte("testValue2"))
	smt.Update([]byte("testKey3"), []byte("testValue3"))
	smt.Update([]byte("testKey4"), []byte("testValue4"))
	smt.Update([]byte("testKey6"), []byte("testValue6"))

	proof1, _ := smt.Prove([]byte("testKey1"))
	proof2, _ := smt.Prove([]byte("testKey2"))
	proof5, _ := smt.Prove([]byte("testKey5"))

	dsmst := NewDeepSparseMerkleSubTree(NewSimpleMap(), sha256.New(), smt.Root())
	dsmst.AddBranch(proof1, []byte("testKey1"), []byte("testValue1"))
	dsmst.AddBranch(proof2, []byte("testKey2"), []byte("testValue2"))
	dsmst.AddBranch(proof5, []byte("testKey5"), defaultValue)

	value, err := dsmst.Get([]byte("testKey1"))
	if err != nil {
		t.Error("returned error when getting value in deep subtree")
	}
	if bytes.Compare(value, []byte("testValue1")) != 0 {
		t.Error("did not get correct value in deep subtree")
	}
	value, err = dsmst.Get([]byte("testKey2"))
	if err != nil {
		t.Error("returned error when getting value in deep subtree")
	}
	if bytes.Compare(value, []byte("testValue2")) != 0 {
		t.Error("did not get correct value in deep subtree")
	}
	value, err = dsmst.Get([]byte("testKey5"))
	if err != nil {
		t.Error("returned error when getting value in deep subtree")
	}
	if bytes.Compare(value, defaultValue) != 0 {
		t.Error("did not get correct value in deep subtree")
	}
	value, err = dsmst.Get([]byte("testKey6"))
	if err == nil {
		t.Error("did not error when getting non-added value in deep subtree")
	}

	dsmst.Update([]byte("testKey1"), []byte("testValue3"))
	dsmst.Update([]byte("testKey2"), defaultValue)
	dsmst.Update([]byte("testKey5"), []byte("testValue5"))

	value, err = dsmst.Get([]byte("testKey1"))
	if err != nil {
		t.Error("returned error when getting value in deep subtree")
	}
	if bytes.Compare(value, []byte("testValue3")) != 0 {
		t.Error("did not get correct value in deep subtree")
	}
	value, err = dsmst.Get([]byte("testKey2"))
	if err != nil {
		t.Error("returned error when getting value in deep subtree")
	}
	if bytes.Compare(value, defaultValue) != 0 {
		t.Error("did not get correct value in deep subtree")
	}
	value, err = dsmst.Get([]byte("testKey5"))
	if err != nil {
		t.Error("returned error when getting value in deep subtree")
	}
	if bytes.Compare(value, []byte("testValue5")) != 0 {
		t.Error("did not get correct value in deep subtree")
	}

	smt.Update([]byte("testKey1"), []byte("testValue3"))
	smt.Update([]byte("testKey2"), defaultValue)
	smt.Update([]byte("testKey5"), []byte("testValue5"))

	if bytes.Compare(smt.Root(), dsmst.Root()) != 0 {
		t.Error("roots of identical standard tree and subtree do not match")
	}
}

func TestDeepSparseMerkleSubTreeBadInput(t *testing.T) {
	smt := NewSparseMerkleTree(NewSimpleMap(), sha256.New())

	smt.Update([]byte("testKey1"), []byte("testValue1"))
	smt.Update([]byte("testKey2"), []byte("testValue2"))
	smt.Update([]byte("testKey3"), []byte("testValue3"))
	smt.Update([]byte("testKey4"), []byte("testValue4"))

	badProof, _ := smt.Prove([]byte("testKey1"))
	badProof.SideNodes[0][0] = byte(0)

	dsmst := NewDeepSparseMerkleSubTree(NewSimpleMap(), sha256.New(), smt.Root())
	err := dsmst.AddBranch(badProof, []byte("testKey1"), []byte("testValue1"))
	if _, ok := err.(*BadProofError); !ok {
		t.Error("did not return BadProofError for bad proof input")
	}
}
