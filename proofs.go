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

    if len(proof) != hasher.Size() * 8 {
        return false
    }

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

// CompactProof compacts a proof, to reduce its size.
func CompactProof(proof [][]byte, hasher hash.Hash) [][]byte {
    bits := emptyBytes(hasher.Size())
    compactProof := make([][]byte, 0)
    for i, node := range proof {
        if bytes.Compare(node, defaultNodes(hasher)[i]) == 0 {
            setBit(bits, i)
        } else {
            nodeCopy := make([]byte, hasher.Size())
            copy(nodeCopy, node)
            compactProof = append(compactProof, nodeCopy)
        }
    }
    return append([][]byte{bits}, compactProof...)
}

// DecompactProof decompacts a proof, so that it can be used for VerifyProof.
func DecompactProof(proof [][]byte, hasher hash.Hash) [][]byte {
    decompactedProof := make([][]byte, hasher.Size() * 8)
    bits := proof[0]
    compactProof := proof[1:]
    position := 0
    for i := 0; i < hasher.Size() * 8; i++ {
        if hasBit(bits, i) == 1 {
            decompactedProof[i] = defaultNodes(hasher)[i]
        } else {
            decompactedProof[i] = compactProof[position]
            position++
        }
    }
    return decompactedProof
}
