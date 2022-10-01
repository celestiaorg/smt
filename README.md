# Sparse Merkle Tree (smt)

A Go library that implements a Sparse Merkle Tree for a key-value map. The tree implements the same optimisations specified in the [Jellyfish Merkle Tree whitepaper][jmt whitepaper] originally designed for the [Libra blockchain][libra whitepaper]. It reduces the number of hash operations required per tree operation to `O(k)` where `k` is the number of non-empty elements in the tree.

[![Tests](https://github.com/celestiaorg/smt/actions/workflows/test.yml/badge.svg)](https://github.com/celestiaorg/smt/actions/workflows/test.yml)
[![codecov](https://codecov.io/gh/celestiaorg/smt/branch/master/graph/badge.svg?token=U3GGEDSA94)](https://codecov.io/gh/celestiaorg/smt)
[![GoDoc](https://godoc.org/github.com/celestiaorg/smt?status.svg)](https://godoc.org/github.com/celestiaorg/smt)

## Installation

```bash
go get github.com/celestiaorg/smt@master
```

## Example

```go
package main

import (
    "crypto/sha256"
    "fmt"

    "github.com/celestiaorg/smt"
)

func main() {
    // Initialise 2 new key-value store to stores the nodes and values of the tree
    nodeStore := smt.NewSimpleMap() // Mapping from hash -> data
    valueStore := smt.NewSimpleMap() // Mapping from path -> value

    // Initialise the smt
    tree := smt.NewSparseMerkleTree(nodeStore, valueStore, sha256.New())

    // Update the key "foo" with the value "bar"
    _, _ = tree.Update([]byte("foo"), []byte("bar"))

    // Generate a Merkle proof for foo=bar
    proof, _ := tree.Prove([]byte("foo"))
    root := tree.Root() // We also need the current tree root for the proof

    // Verify the Merkle proof for foo=bar
    if smt.VerifyProof(proof, root, []byte("foo"), []byte("bar"), sha256.New()) {
        fmt.Println("Proof verification succeeded.")
    } else {
        fmt.Println("Proof verification failed.")
    }
}
```

## Development

Run `make` to see all the options available

## General Improvements / TODOs

- [ ] Use the `require` test module to simplify unit tests
- [ ] Create types for `sideNodes`, `root`, etc...

[libra whitepaper]: https://diem-developers-components.netlify.app/papers/the-diem-blockchain/2020-05-26.pdf
[jmt whitepaper]: https://developers.diem.com/papers/jellyfish-merkle-tree/2021-01-14.pdf

### [Delete me later] personal checklist

- [x] ├── LICENSE
- [x] ├── Makefile
- [x] ├── README.md
- [ ] ├── bench_test.go
- [ ] ├── bulk_test.go
- [ ] ├── deepsubtree.go
- [ ] ├── deepsubtree_test.go
- [ ] ├── fuzz
- [ ] │   ├── delete
- [ ] │   │   └── fuzz.go
- [ ] │   └── fuzz.go
- [x] ├── go.mod
- [x] ├── go.sum
- [ ] ├── mapstore.go
- [ ] ├── mapstore_test.go
- [ ] ├── options.go
- [ ] ├── oss-fuzz-build.sh
- [ ] ├── proofs.go
- [ ] ├── proofs_test.go
- [x] ├── smt.go
- [ ] ├── smt_test.go
- [x] ├── treehasher.go
- [x] ├── treehasher_test.go
- [x] └── utils.go
