# smt

A Go library that implements a Sparse Merkle tree for a key-value map.

[![Build Status](https://travis-ci.org/lazyledger/smt.svg?branch=master)](https://travis-ci.org/lazyledger/smt)
[![Coverage Status](https://coveralls.io/repos/github/lazyledger/smt/badge.svg?branch=master)](https://coveralls.io/github/lazyledger/smt?branch=master)
[![GoDoc](https://godoc.org/github.com/lazyledger/smt?status.svg)](https://godoc.org/github.com/lazyledger/smt)

Thanks to Vitalik Buterin who provided the [original Python prototype](https://ethresear.ch/t/data-availability-proof-friendly-state-tree-transitions/1453/6) that some of this library is inspired from.

## Example

```go
package main

import(
    "fmt"
    "crypto/sha256"
    "github.com/lazyledger/smt"
)

func main() {
    // Initialise a new key-value store to store the nodes of the tree
    store := smt.NewSimpleMap()
    // Initialise the tree
    tree := smt.NewSparseMerkleTree(store, sha256.New())

    // Update the key "foo" with the value "bar"
    tree.Update([]byte("foo"), []byte("bar"))

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

## Future wishlist

- **Garbage collection for obsolete nodes.** When tree is updated, obsolete nodes are not garbage collected, and so storage growth is unbounded. This is desirable for accessing previous revisions of the tree (for example, if you need to revert to a previous block in a blockchain due to a chain reorganisation caused by the chain's consensus algorithm), but otherwise undesirable for storage size. A future wishlist item is to extend the library to allow for an optional garbage collected version of the tree, though this requires further research.
- **Tree sharding to process updates in parallel.** At the moment, the tree can only safely handle one update at a time. It would be desirable to shard the tree into multiple subtrees and allow parallel updates to the subtrees.
