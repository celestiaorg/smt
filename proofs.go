package smt

import(
    "hash"
    "bytes"
)

func VerifyProof(sideNodes [][]byte, root []byte, key []byte, value []byte, hasher hash.Hash) bool {
    hasher.Write(key)
    path := hasher.Sum(nil)
    hasher.Reset()

    hasher.Write(value)
    currentHash := hasher.Sum(nil)
    hasher.Reset()

    for i := hasher.Size() * 8 - 1; i >= 0; i-- {
        if hasBit(path, i) == right {
            hasher.Write(append(sideNodes[i], currentHash...))
            currentHash = hasher.Sum(nil)
            hasher.Reset()
        } else {
            hasher.Write(append(currentHash, sideNodes[i]...))
            currentHash = hasher.Sum(nil)
            hasher.Reset()
        }
    }

    return bytes.Compare(currentHash, root) == 0
}
