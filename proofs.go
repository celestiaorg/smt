package smt

import(
    "hash"
    "bytes"
)

// VerifyProof verifies a Merkle proof.
func VerifyProof(proof [][]byte, root []byte, key []byte, value []byte, hasher hash.Hash) bool {
    hasher.Write(key)
    path := hasher.Sum(nil)
    hasher.Reset()

    hasher.Write(value)
    currentHash := hasher.Sum(nil)
    hasher.Reset()

    for i := hasher.Size() * 8 - 1; i >= 0; i-- {
        node := make([]byte, hasher.Size())
        copy(node, proof[i])
        if hasBit(path, i) == right {
            hasher.Write(append(node, currentHash...))
            currentHash = hasher.Sum(nil)
            hasher.Reset()
        } else {
            hasher.Write(append(currentHash, node...))
            currentHash = hasher.Sum(nil)
            hasher.Reset()
        }
    }

    return bytes.Compare(currentHash, root) == 0
}

func CompactProof(proof [][]byte, hasher hash.Hash) {
    bits := emptyBytes(hasher.Size())
    for i, node := range proof {
        if bytes.Compare(node, defaultNodes(hasher)[i]) == 0 {
            setBit(bits, i)
        }
    }
}
