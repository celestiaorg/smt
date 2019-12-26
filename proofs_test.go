package smt

import(
    "hash"
    "math/rand"
    "crypto/sha256"
    "testing"
    "reflect"
)

func TestProofs(t *testing.T) {
    testProofs(t, sha256.New())
}

func testProofs(t *testing.T, hasher hash.Hash) {
    sm := NewSimpleMap()
    smt := NewSparseMerkleTree(sm, hasher)
    var err error

    badProof := make([][]byte, hasher.Size() * 8)
    for i := 0; i < len(badProof); i++ {
        badProof[i] = make([]byte, hasher.Size())
        rand.Read(badProof[i])
    }

    smt.Update([]byte("testKey"), []byte("testValue"))

    proof, err := smt.Prove([]byte("testKey"))
    if err != nil {
        t.Error("error returned when trying to prove inclusion")
    }
    result := VerifyProof(proof, smt.root, []byte("testKey"), []byte("testValue"), hasher)
    if !result {
        t.Error("valid proof failed to verify")
    }
    result = VerifyProof(proof, smt.root, []byte("testKey"), []byte("badValue"), hasher)
    if result {
        t.Error("invalid proof verification returned true")
    }
    result = VerifyProof(proof, smt.root, []byte("testKey1"), []byte("testValue"), hasher)
    if result {
        t.Error("invalid proof verification returned true")
    }
    result = VerifyProof(badProof, smt.root, []byte("testKey"), []byte("testValue"), hasher)
    if result {
        t.Error("invalid proof verification returned true")
    }

    smt.Update([]byte("testKey2"), []byte("testValue"))

    proof, err = smt.Prove([]byte("testKey"))
    if err != nil {
        t.Error("error returned when trying to prove inclusion")
    }
    result = VerifyProof(proof, smt.root, []byte("testKey"), []byte("testValue"), hasher)
    if !result {
        t.Error("valid proof failed to verify")
    }
    result = VerifyProof(proof, smt.root, []byte("testKey"), []byte("badValue"), hasher)
    if result {
        t.Error("invalid proof verification returned true")
    }
    result = VerifyProof(proof, smt.root, []byte("testKey2"), []byte("testValue"), hasher)
    if result {
        t.Error("invalid proof verification returned true")
    }
    result = VerifyProof(badProof, smt.root, []byte("testKey"), []byte("testValue"), hasher)
    if result {
        t.Error("invalid proof verification returned true")
    }

    proof, err = smt.Prove([]byte("testKey2"))
    if err != nil {
        t.Error("error returned when trying to prove inclusion")
        t.Log(err)
    }
    result = VerifyProof(proof, smt.root, []byte("testKey2"), []byte("testValue"), hasher)
    if !result {
        t.Error("valid proof failed to verify")
    }
    result = VerifyProof(proof, smt.root, []byte("testKey2"), []byte("badValue"), hasher)
    if result {
        t.Error("invalid proof verification returned true")
    }
    result = VerifyProof(proof, smt.root, []byte("testKey3"), []byte("testValue"), hasher)
    if result {
        t.Error("invalid proof verification returned true")
    }
    result = VerifyProof(badProof, smt.root, []byte("testKey"), []byte("testValue"), hasher)
    if result {
        t.Error("invalid proof verification returned true")
    }

    proof, err = smt.Prove([]byte("testKey3"))
    if err != nil {
        t.Error("error returned when trying to prove inclusion on empty key")
        t.Log(err)
    }
    result = VerifyProof(proof, smt.root, []byte("testKey3"), defaultValue, hasher)
    if !result {
        t.Error("valid proof on empty key failed to verify")
    }
    result = VerifyProof(proof, smt.root, []byte("testKey3"), []byte("badValue"), hasher)
    if result {
        t.Error("invalid proof verification on empty key returned true")
    }
    result = VerifyProof(proof, smt.root, []byte("testKey2"), defaultValue, hasher)
    if result {
        t.Error("invalid proof verification on empty key returned true")
    }
    result = VerifyProof(badProof, smt.root, []byte("testKey"), []byte("testValue"), hasher)
    if result {
        t.Error("invalid proof verification on empty key returned true")
    }

    compactProof, err := CompactProof(proof, hasher)
    decompactedProof, err := DecompactProof(compactProof, hasher)
    if !reflect.DeepEqual(proof, decompactedProof) {
        t.Error("compacting and decompacting proof returns a different proof than the original proof")
    }

    badProof2 := make([][]byte, hasher.Size() * 8 + 1)
    for i := 0; i < len(badProof); i++ {
        badProof[i] = make([]byte, hasher.Size())
        rand.Read(badProof[i])
    }
    badProof3 := make([][]byte, hasher.Size() * 8 - 1)
    for i := 0; i < len(badProof); i++ {
        badProof[i] = make([]byte, hasher.Size())
        rand.Read(badProof[i])
    }
    badProof4 := make([][]byte, hasher.Size() * 8)
    for i := 0; i < len(badProof); i++ {
        badProof[i] = make([]byte, hasher.Size() - 1)
        rand.Read(badProof[i])
    }
    badProof5 := make([][]byte, hasher.Size() * 8)
    for i := 0; i < len(badProof); i++ {
        badProof[i] = make([]byte, hasher.Size() + 1)
        rand.Read(badProof[i])
    }
    badProof6 := make([][]byte, hasher.Size() * 8)
    for i := 0; i < len(badProof); i++ {
        badProof[i] = make([]byte, 1)
        rand.Read(badProof[i])
    }

    result = VerifyProof(badProof2, smt.root, []byte("testKey3"), defaultValue, hasher)
    if result {
        t.Error("invalid proof verification returned true")
    }
    result = VerifyProof(badProof3, smt.root, []byte("testKey3"), defaultValue, hasher)
    if result {
        t.Error("invalid proof verification returned true")
    }
    result = VerifyProof(badProof4, smt.root, []byte("testKey3"), defaultValue, hasher)
    if result {
        t.Error("invalid proof verification returned true")
    }
    result = VerifyProof(badProof5, smt.root, []byte("testKey3"), defaultValue, hasher)
    if result {
        t.Error("invalid proof verification returned true")
    }
    result = VerifyProof(badProof6, smt.root, []byte("testKey3"), defaultValue, hasher)
    if result {
        t.Error("invalid proof verification returned true")
    }

    compactProof, err = CompactProof(badProof2, hasher)
    if err == nil {
        t.Error("CompactProof did not return error on bad proof size")
    }
    compactProof, err = CompactProof(badProof3, hasher)
    if err == nil {
        t.Error("CompactProof did not return error on bad proof size")
    }

    decompactedProof, err = DecompactProof(badProof3, hasher)
    if err == nil {
        t.Error("DecompactProof did not return error on bad proof size")
    }
    decompactedProof, err = DecompactProof([][]byte{}, hasher)
    if err == nil {
        t.Error("DecompactProof did not return error on bad proof size")
    }

    proof, err = smt.ProveCompact([]byte("testKey2"))
    if err != nil {
        t.Error("error returned when trying to prove inclusion")
        t.Log(err)
    }
    result = VerifyCompactProof(proof, smt.root, []byte("testKey2"), []byte("testValue"), hasher)
    if !result {
        t.Error("valid proof failed to verify")
    }
    result = VerifyCompactProof(proof, smt.root, []byte("testKey2"), []byte("badValue"), hasher)
    if result {
        t.Error("invalid proof verification returned true")
    }
    result = VerifyCompactProof(proof, smt.root, []byte("testKey3"), []byte("testValue"), hasher)
    if result {
        t.Error("invalid proof verification returned true")
    }
    result = VerifyCompactProof(badProof, smt.root, []byte("testKey"), []byte("testValue"), hasher)
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
    result = VerifyCompactProof(proof, root, []byte("testKey2"), []byte("testValue"), hasher)
    if !result {
        t.Error("valid proof failed to verify")
    }
    result = VerifyCompactProof(proof, root, []byte("testKey2"), []byte("badValue"), hasher)
    if result {
        t.Error("invalid proof verification returned true")
    }
    result = VerifyCompactProof(proof, root, []byte("testKey3"), []byte("testValue"), hasher)
    if result {
        t.Error("invalid proof verification returned true")
    }
    result = VerifyCompactProof(badProof, root, []byte("testKey"), []byte("testValue"), hasher)
    if result {
        t.Error("invalid proof verification returned true")
    }

    proof, err = smt.ProveForRoot([]byte("testKey2"), root)
    if err != nil {
        t.Error("error returned when trying to prove inclusion")
        t.Log(err)
    }
    result = VerifyProof(proof, root, []byte("testKey2"), []byte("testValue"), hasher)
    if !result {
        t.Error("valid proof failed to verify")
    }
    result = VerifyProof(proof, root, []byte("testKey2"), []byte("badValue"), hasher)
    if result {
        t.Error("invalid proof verification returned true")
    }
    result = VerifyProof(proof, root, []byte("testKey3"), []byte("testValue"), hasher)
    if result {
        t.Error("invalid proof verification returned true")
    }
    result = VerifyProof(badProof, root, []byte("testKey"), []byte("testValue"), hasher)
    if result {
        t.Error("invalid proof verification returned true")
    }
}
