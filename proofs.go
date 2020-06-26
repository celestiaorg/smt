package smt

import(
    "hash"
    "bytes"
    "errors"
)

// VerifyProof verifies a Merkle proof.
func VerifyProof(proof [][]byte, root []byte, key []byte, value []byte, hasher hash.Hash) bool {
    th := newTreeHasher(hasher)
    path := th.path(key)

    currentHash := th.digestLeaf(path, value)

    if len(proof) != hasher.Size() * 8 {
        return false
    }

    for i := hasher.Size() * 8 - 1; i >= 0; i-- {
        node := make([]byte, hasher.Size())
        copy(node, proof[i])
        if len(node) != hasher.Size() {
            return false
        }
        if hasBit(path, i) == right {
            currentHash = th.digestNode(node, currentHash)
        } else {
            currentHash = th.digestNode(currentHash, node)
        }
    }

    return bytes.Compare(currentHash, root) == 0
}

// VerifyCompactProof verifies a compacted Merkle proof.
func VerifyCompactProof(proof [][]byte, root []byte, key []byte, value []byte, hasher hash.Hash) bool {
    decompactedProof, err := DecompactProof(proof, hasher)
    if err != nil {
        return false
    }
    return VerifyProof(decompactedProof, root, key, value, hasher)
}

// CompactProof compacts a proof, to reduce its size.
func CompactProof(proof [][]byte, hasher hash.Hash) ([][]byte, error) {
    if len(proof) != hasher.Size() * 8 {
        return nil, errors.New("bad proof size")
    }

    bits := emptyBytes(hasher.Size())
    var compactProof [][]byte
    for i := 0; i < hasher.Size() * 8; i++ {
        node := make([]byte, hasher.Size())
        copy(node, proof[i])
        if bytes.Compare(node, defaultNodes(hasher)[i]) == 0 {
            setBit(bits, i)
        } else {
            compactProof = append(compactProof, node)
        }
    }
    return append([][]byte{bits}, compactProof...), nil
}

// DecompactProof decompacts a proof, so that it can be used for VerifyProof.
func DecompactProof(proof [][]byte, hasher hash.Hash) ([][]byte, error) {
    if len(proof) == 0 ||
        len(proof[0]) != hasher.Size() ||
        len(proof) != (hasher.Size() * 8 - countSetBits(proof[0])) + 1 {
        return nil, errors.New("invalid proof size")
    }

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
    return decompactedProof, nil
}
