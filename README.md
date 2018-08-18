# smt

A Go library that implements a Sparse Merkle tree.

When tree is updated, obsolete nodes are not garbage collected, and so storage growth is unbounded. This is desirable for accessing previous revisions of the tree, but otherwise undesirable for storage size. A future wishlist item is to extend the library to allow for an optional garbage collected version of the tree, though this requires further research.

[![Build Status](https://travis-ci.org/musalbas/smt.svg?branch=master)](https://travis-ci.org/musalbas/smt)
[![Coverage Status](https://coveralls.io/repos/github/musalbas/smt/badge.svg?branch=master)](https://coveralls.io/github/musalbas/smt?branch=master)
[![GoDoc](https://godoc.org/github.com/musalbas/smt?status.svg)](https://godoc.org/github.com/musalbas/smt)

## Future wishlist

- [ ] Garbage collection for obsolete nodes.
- [ ] Tree sharding to process updates in parallel.
