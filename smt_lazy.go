package smt

import (
	"bytes"
	"hash"
)

var (
	_ treeNode = (*innerNode)(nil)
	_ treeNode = (*leafNode)(nil)
)

type innerNode struct {
	leftChild, rightChild treeNode
	persisted             bool
	// cached hash digest
	digest []byte
}

type leafNode struct {
	path      []byte
	valueHash []byte
	persisted bool
	// cached hash digest
	digest []byte
}

// represents uncached persisted node
type stubNode struct {
	digest []byte
}

type treeNode interface {
	Persisted() bool
	cachedDigest() []byte
}

type LazySMT struct {
	*SparseMerkleTree
	cache treeNode
	// hashes of persisted nodes deleted in cache
	orphans [][]byte
}

func NewLazySMT(nodes MapStore, hasher hash.Hash, options ...Option) *LazySMT {
	return &LazySMT{SparseMerkleTree: NewSparseMerkleTree(nodes, hasher, options...)}
}

func ImportLazySMT(
	nodes MapStore, hasher hash.Hash, root []byte, options ...Option,
) (smt *LazySMT, err error) {
	smt = &LazySMT{
		SparseMerkleTree: ImportSparseMerkleTree(nodes, hasher, root, options...),
	}
	smt.cache = &stubNode{smt.root}
	// todo - optional eager caching
	// smt.cache, err = smt.recursiveLoad(smt.root)
	// if err != nil {
	// 	smt = nil
	// }
	return
}

func (smt *LazySMT) GetDescend(key []byte) ([]byte, error) {
	path := smt.ph.Path(key)
	leaf, err := smt.recursiveGet(smt.cache, 0, path)
	if err != nil {
		return nil, err
	}
	if leaf == nil {
		return defaultValue, nil
	}
	return leaf.valueHash, nil
}

func (smt *LazySMT) recursiveGet(node treeNode, depth int, path []byte) (*leafNode, error) {
	node, err := smt.resolveStub(node)
	if err != nil {
		return nil, err
	}
	if node == nil {
		return nil, nil
	}
	if leaf, ok := node.(*leafNode); ok {
		if bytes.Equal(path, leaf.path) {
			return leaf, nil
		}
		return nil, nil
	}
	var child treeNode
	inner := node.(*innerNode)
	if getBitAtFromMSB(path, depth) == left {
		child = inner.leftChild
	} else {
		child = inner.rightChild
	}
	return smt.recursiveGet(child, depth+1, path)
}

// todo - change method signatures
func (smt *LazySMT) Update(key []byte, value []byte) ([]byte, error) {
	path := smt.ph.Path(key)
	var orphans []treeNode
	tree, err := smt.recursiveUpdate(smt.cache, 0, path, smt.hashValue(value), &orphans)
	if err != nil {
		return nil, err
	}
	smt.orphans = append(smt.orphans, persistedNodeDigests(orphans)...)
	smt.cache = tree
	return smt.Root(), nil
}

func (smt *LazySMT) recursiveUpdate(
	node treeNode, depth int, path, value []byte, orphans *[]treeNode,
) (treeNode, error) {
	node, err := smt.resolveStub(node)
	if err != nil {
		return nil, err
	}

	newLeaf := &leafNode{path: path, valueHash: value}
	// Empty subtree is always replaced by a single leaf
	if node == nil {
		return newLeaf, nil
	}
	if leaf, ok := node.(*leafNode); ok {
		// todo (optim) - can just count [depth:]
		prefixlen := countCommonPrefix(path, leaf.path)
		if prefixlen == smt.depth() { // replace leaf if paths are equal
			*orphans = append(*orphans, node)
			return newLeaf, nil
		}
		// We must create a "list" of single-branch inner nodes
		var listRoot treeNode
		prev := &listRoot
		for d := depth; d < prefixlen; d++ {
			inner := &innerNode{}
			*prev = inner
			if getBitAtFromMSB(path, d) == left {
				prev = &inner.leftChild
			} else {
				prev = &inner.rightChild
			}
		}
		if getBitAtFromMSB(path, prefixlen) == left {
			*prev = &innerNode{leftChild: newLeaf, rightChild: leaf}
		} else {
			*prev = &innerNode{leftChild: leaf, rightChild: newLeaf}
		}
		return listRoot, nil
	}

	*orphans = append(*orphans, node)
	var child *treeNode
	inner := node.(*innerNode).clone()
	if getBitAtFromMSB(path, depth) == left {
		child = &inner.leftChild
	} else {
		child = &inner.rightChild
	}
	*child, err = smt.recursiveUpdate(*child, depth+1, path, value, orphans)
	if err != nil {
		return nil, err
	}
	return inner, nil
}

// todo - change method signatures
func (smt *LazySMT) Delete(key []byte) ([]byte, error) {
	path := smt.ph.Path(key)
	var orphans []treeNode
	tree, err := smt.recursiveDelete(smt.cache, 0, path, &orphans)
	if err != nil {
		return nil, err
	}
	smt.orphans = append(smt.orphans, persistedNodeDigests(orphans)...)
	smt.cache = tree
	return smt.Root(), nil
}

func (smt *LazySMT) recursiveDelete(node treeNode, depth int, path []byte, orphans *[]treeNode,
) (treeNode, error) {
	node, err := smt.resolveStub(node)
	if err != nil {
		return nil, err
	}

	if node == nil {
		return nil, errKeyAlreadyEmpty
	}
	if leaf, ok := node.(*leafNode); ok {
		if !bytes.Equal(path, leaf.path) {
			return nil, errKeyAlreadyEmpty
		}
		*orphans = append(*orphans, node)
		return nil, nil
	}

	*orphans = append(*orphans, node)
	var child, sib *treeNode
	inner := node.(*innerNode).clone()
	if getBitAtFromMSB(path, depth) == left {
		child, sib = &inner.leftChild, &inner.rightChild
	} else {
		child, sib = &inner.rightChild, &inner.leftChild
	}
	*child, err = smt.recursiveDelete(*child, depth+1, path, orphans)
	if err != nil {
		return nil, err
	}
	*sib, err = smt.resolveStub(*sib)
	if err != nil {
		return nil, err
	}
	// We can only replace this node with a leaf -
	// Inner nodes exist at a fixed depth, and can't be moved.
	if *child == nil {
		if _, ok := (*sib).(*leafNode); ok {
			return *sib, nil
		}
	}
	if *sib == nil {
		if _, ok := (*child).(*leafNode); ok {
			return *child, nil
		}
	}
	return inner, nil
}

func (smt *LazySMT) Prove(key []byte) (proof SparseMerkleProof, err error) {
	path := smt.ph.Path(key)
	var siblings []treeNode
	var sib treeNode

	node := smt.cache
	for depth := 0; depth < smt.depth(); depth++ {
		node, err = smt.resolveStub(node)
		if err != nil {
			return
		}
		if node == nil {
			break
		}
		if _, ok := node.(*leafNode); ok {
			break
		}
		inner := node.(*innerNode)
		if getBitAtFromMSB(path, depth) == left {
			node, sib = inner.leftChild, inner.rightChild
		} else {
			node, sib = inner.rightChild, inner.leftChild
		}
		siblings = append(siblings, sib)
	}

	// Deal with non-membership proofs. If there is no leaf on this path,
	// we do not need to add anything else to the proof.
	var leafData []byte
	if node != nil {
		leaf := node.(*leafNode)
		if !bytes.Equal(leaf.path, path) {
			// This is a non-membership proof that involves showing a different leaf.
			// Add the leaf data to the proof.
			_, leafData = smt.th.digestLeaf(leaf.path, leaf.valueHash)
		}
	}
	// Hash siblings from bottom up.
	var sideNodes [][]byte
	for i, _ := range siblings {
		var sideNode []byte
		sibling := siblings[len(siblings)-1-i]
		sideNode = smt.hashNode(sibling)
		sideNodes = append(sideNodes, sideNode)
	}

	proof = SparseMerkleProof{
		SideNodes:             sideNodes,
		NonMembershipLeafData: leafData,
	}
	if sib != nil {
		sib, err = smt.resolveStub(sib)
		if err != nil {
			return
		}
		proof.SiblingData = smt.serialize(sib)
	}
	return
}

func (smt *LazySMT) recursiveLoad(hash []byte) (treeNode, error) {
	return smt.resolve(hash, smt.recursiveLoad)
}

// resolves a stub into a cached node
func (smt *LazySMT) resolveStub(node treeNode) (treeNode, error) {
	stub, ok := node.(*stubNode)
	if !ok {
		return node, nil
	}
	resolver := func(hash []byte) (treeNode, error) {
		return &stubNode{hash}, nil
	}
	return smt.resolve(stub.digest, resolver)
}

func (smt *LazySMT) resolve(hash []byte, resolver func([]byte) (treeNode, error),
) (ret treeNode, err error) {
	if bytes.Equal(smt.th.placeholder(), hash) {
		return
	}
	data, err := smt.nodes.Get(hash)
	if err != nil {
		return
	}
	if isLeaf(data) {
		leaf := leafNode{persisted: true, digest: hash}
		leaf.path, leaf.valueHash = parseLeaf(data, smt.ph)
		return &leaf, nil
	}
	leftHash, rightHash := smt.th.parseNode(data)
	inner := innerNode{persisted: true, digest: hash}
	inner.leftChild, err = resolver(leftHash)
	if err != nil {
		return
	}
	inner.rightChild, err = resolver(rightHash)
	if err != nil {
		return
	}
	return &inner, nil
}

func (smt *LazySMT) Save() (err error) {
	if err = smt.recursiveSave(smt.cache, 0); err != nil {
		return
	}
	// All orphans are persisted w/ cached digests, so we don't need to check for null
	for _, hash := range smt.orphans {
		if err = smt.nodes.Delete(hash); err != nil {
			return
		}
	}
	smt.orphans = nil
	smt.root = smt.Root()
	return
}

func (smt *LazySMT) recursiveSave(node treeNode, depth int) error {
	if node != nil && node.Persisted() {
		return nil
	}
	switch n := node.(type) {
	case *leafNode:
		n.persisted = true
	case *innerNode:
		n.persisted = true
		if err := smt.recursiveSave(n.leftChild, depth+1); err != nil {
			return err
		}
		if err := smt.recursiveSave(n.rightChild, depth+1); err != nil {
			return err
		}
	default:
		return nil
	}
	return smt.nodes.Set(smt.hashNode(node), smt.serialize(node))
}

func (smt *LazySMT) Root() []byte {
	return smt.hashNode(smt.cache)
}

func (node *leafNode) Persisted() bool  { return node.persisted }
func (node *innerNode) Persisted() bool { return node.persisted }
func (node *stubNode) Persisted() bool  { return true }

func (node *leafNode) cachedDigest() []byte  { return node.digest }
func (node *innerNode) cachedDigest() []byte { return node.digest }
func (node *stubNode) cachedDigest() []byte  { return node.digest }

func (smt *LazySMT) serialize(node treeNode) (data []byte) {
	switch n := node.(type) {
	case *stubNode:
		panic("serialize(stubNode)")
	case *leafNode:
		return encodeLeaf(n.path, n.valueHash)
	case *innerNode:
		var lh, rh []byte
		lh = smt.hashNode(n.leftChild)
		rh = smt.hashNode(n.rightChild)
		return encodeInner(lh, rh)
	}
	return nil
}

func (smt *LazySMT) hashNode(node treeNode) []byte {
	if node == nil {
		return smt.th.placeholder()
	}
	var cache *[]byte
	switch n := node.(type) {
	case *stubNode:
		return n.digest
	case *leafNode:
		cache = &n.digest
	case *innerNode:
		cache = &n.digest
	}
	if *cache == nil {
		*cache = smt.th.digest(smt.serialize(node))
	}
	return *cache
}

func (inner *innerNode) clone() *innerNode {
	return &innerNode{
		leftChild:  inner.leftChild,
		rightChild: inner.rightChild,
	}
}

func persistedNodeDigests(nodes []treeNode) (ret [][]byte) {
	for _, node := range nodes {
		if node.Persisted() {
			ret = append(ret, node.cachedDigest())
		}
	}
	return
}
