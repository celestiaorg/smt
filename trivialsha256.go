package smt

import (
    "hash"
    "crypto/sha256"
    "bytes"
    "math/big"
    "fmt"
)

var defaultNode = bytes.Repeat([]byte{0}, 32)

type trivialDigest struct {
    data []byte
    sha256 hash.Hash
}

// NewTrivialSHA256Hasher returns a SHA256-based hasher that is trivial to compute on zero inputs.
func NewTrivialSHA256Hasher() hash.Hash {
    return &trivialDigest{
        sha256: sha256.New(),
    }
}

func (d *trivialDigest) Size() int {
    return d.sha256.Size()
}

func (d *trivialDigest) BlockSize() int {
    return d.sha256.Size()
}

func (d *trivialDigest) Reset() {
    d.data = nil
}

func (d *trivialDigest) Write(p []byte) (int, error) {
    d.data = append(d.data, p...)
    return len(p), nil
}

func (d *trivialDigest) Sum(in []byte) []byte {
    sum := make([]byte, d.Size())

    if d.data[0] == leafPrefix {
        if bytes.Compare(d.data[1:], defaultValue) == 0 {
            copy(sum, defaultNode)
        } else {
            sum = d.baseDigest(d.data)
        }
    } else {
        l := d.data[1:d.Size()+1]
        r := d.data[d.Size()+1:]

        lInt := new(big.Int)
        lInt.SetBytes(l)
        rInt := new(big.Int)
        rInt.SetBytes(r)

        lower := new(big.Int).Exp(big.NewInt(2), big.NewInt(240), nil)
        upper := new(big.Int).Exp(big.NewInt(2), big.NewInt(255), nil)

        if (bytes.Compare(l, defaultNode) != 0 && bytes.Compare(r, defaultNode) != 0) ||
            lInt.Cmp(upper) != -1 || rInt.Cmp(upper) != -1 ||
            lInt.Cmp(lower) == -1 || rInt.Cmp(lower) == -1 {
            sum = d.normaliseDigest(d.data)
        } else if bytes.Compare(l, defaultNode) == 0 && bytes.Compare(r, defaultNode) == 0 {
            copy(sum, defaultNode)
        } else {
            z := new(big.Int)
            if bytes.Compare(l, defaultNode) == 0 {
                z.SetBytes(r)
                z.Mul(z, big.NewInt(2))
            } else {
                z.SetBytes(l)
                z.Mul(z, big.NewInt(2))
                z.Add(z, big.NewInt(1))
            }
            sum = z.Bytes()
            for len(sum) < d.Size() {
                sum = append([]byte{0}, sum...)
            }
            fmt.Println(len(sum))
            fmt.Println(sum)
        }
    }

    return append(in, sum...)
}

func (d *trivialDigest) baseDigest(data []byte) []byte {
    d.sha256.Write(data)
    sum := d.sha256.Sum(nil)
    d.sha256.Reset()
    return sum
}

func (d *trivialDigest) normaliseDigest(data []byte) []byte {
    sum := d.baseDigest(data)
    sum[0] = byte(0)
    sum[1] = byte(1)
    setBit(sum, 16)
    return sum
}
