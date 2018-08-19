package smt

import(
    "math/rand"
    "crypto/sha256"
    "testing"
    "reflect"
)

func TestProofs(t *testing.T) {
    sm := NewSimpleMap()
    smt := NewSparseMerkleTree(sm, sha256.New())
    var err error

    badProof := make([][]byte, sha256.New().Size() * 8)
    for i := 0; i < len(badProof); i++ {
        badProof[i] = make([]byte, sha256.New().Size())
        rand.Read(badProof[i])
    }

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

    if !reflect.DeepEqual(proof, DecompactProof(CompactProof(proof, sha256.New()), sha256.New())) {
        t.Error("compacting and decompacting proof returns a different proof than the original proof")
    }

    badProof2 := make([][]byte, sha256.New().Size() * 8 + 1)
    for i := 0; i < len(badProof); i++ {
        badProof[i] = make([]byte, sha256.New().Size())
        rand.Read(badProof[i])
    }
    badProof3 := make([][]byte, sha256.New().Size() * 8 - 1)
    for i := 0; i < len(badProof); i++ {
        badProof[i] = make([]byte, sha256.New().Size())
        rand.Read(badProof[i])
    }
    badProof4 := make([][]byte, sha256.New().Size() * 8)
    for i := 0; i < len(badProof); i++ {
        badProof[i] = make([]byte, sha256.New().Size() - 1)
        rand.Read(badProof[i])
    }
    badProof5 := make([][]byte, sha256.New().Size() * 8)
    for i := 0; i < len(badProof); i++ {
        badProof[i] = make([]byte, sha256.New().Size() + 1)
        rand.Read(badProof[i])
    }
    badProof6 := make([][]byte, sha256.New().Size() * 8)
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
}
