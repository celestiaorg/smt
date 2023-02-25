package smt

import (
	"bytes"
	"hash"
)

// ASK(reviewer): Help clarify terminology:
// - Terms used through the codebase: `data`, `value`, `hash`, `path`, `digest`
// - Current understanding:
//   - `data` is simply `valueHash` determined using the `digest` function.
//   - `hash`` is synonymous to `digest`
//   - Leaf `value`: (prefix, path, userDataDigest)
//   - Node `value`: (prefix, leftData, rightData)

// From the whitepaper:
// 			Leaf node is a node that stores user value at the bottom of the tree. Besides the data, it also
// 			contains the key used for querying the tree of the node and the digest of the data. The nibble
// 			path field of a leaf node key must be a prefix of its key.

var (
	leafPrefix = []byte{0} // prefix used for the path of each leaf in the three
	nodePrefix = []byte{1} // prefix used for the path of each node in the three
)

// type Node struct {
// 	isLeaf bool
// 	hash   []byte
// 	data   []byte
// }

type treeHasher struct {
	hasher    hash.Hash
	zeroValue []byte // ASK(reviewer): rename to `emptyNode`?
}

func newTreeHasher(hasher hash.Hash) *treeHasher {
	th := treeHasher{hasher: hasher}
	th.zeroValue = make([]byte, th.pathSize())

	return &th
}

func (th *treeHasher) path(key []byte) []byte {
	return th.digest(key)
}

func (th *treeHasher) digest(data []byte) []byte {
	// TODO: Need to add a lock inside of `treeHasher` to avoid race conditions here.
	th.hasher.Write(data)
	sum := th.hasher.Sum(nil)
	th.hasher.Reset()
	return sum
}

// value: (prefix, path, userDataDigest)
// Alternative interpretations of return value:
// 	(hash, value)
// 	(hash(value), value)
// 	(valueHash, value)
// 	(valueDigest, value)
func (th *treeHasher) digestLeaf(path, data []byte) (hash, value []byte) {
	value = make([]byte, 0, len(leafPrefix)+len(path)+len(data))
	value = append(value, leafPrefix...)
	value = append(value, path...)
	value = append(value, data...)

	return th.digest(value), value
}

func (th *treeHasher) parseLeaf(value []byte) (path, data []byte) {
	path = value[len(leafPrefix) : th.pathSize()+len(leafPrefix)]
	data = value[len(leafPrefix)+th.pathSize():]
	return
}

func (th *treeHasher) isLeaf(data []byte) bool {
	return bytes.Equal(data[:len(leafPrefix)], leafPrefix)
}

func (th *treeHasher) digestNode(leftData, rightData []byte) (hash, value []byte) {
	value = make([]byte, 0, len(nodePrefix)+len(leftData)+len(rightData))
	value = append(value, nodePrefix...)
	value = append(value, leftData...)
	value = append(value, rightData...)

	return th.digest(value), value
}

func (th *treeHasher) parseNode(value []byte) (leftData, rightData []byte) {
	leftData = value[len(nodePrefix) : th.pathSize()+len(nodePrefix)]
	rightData = value[len(nodePrefix)+th.pathSize():]
	return
}

func (th *treeHasher) pathSize() int {
	return th.hasher.Size()
}

func (th *treeHasher) placeholder() []byte {
	return th.zeroValue
}
