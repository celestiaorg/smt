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
	// Cached hash digest
	digest []byte
}

type leafNode struct {
	path      []byte
	valueHash []byte
	persisted bool
	// Cached hash digest
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

type SMT struct {
	BaseSMT
	savedRoot []byte
	// Current state of tree
	tree treeNode
	// Hashes of persisted nodes deleted from tree
	orphans [][]byte
}

func NewSMT(nodes MapStore, hasher hash.Hash, options ...Option) *SMT {
	smt := BaseSMT{
		th:    newTreeHasher(hasher),
		nodes: nodes,
	}
	for _, option := range options {
		option(&smt)
	}
	if smt.ph == nil {
		smt.ph = smt.th
	}
	return &SMT{BaseSMT: smt}
}

func ImportSMT(nodes MapStore, hasher hash.Hash, root []byte, options ...Option) *SMT {
	smt := NewSMT(nodes, hasher, options...)
	smt.tree = &stubNode{root}
	smt.savedRoot = root
	return smt
}

func (smt *SMT) Get(key []byte) ([]byte, error) {
	path := smt.ph.Path(key)
	leaf, err := smt.recursiveGet(smt.tree, 0, path)
	if err != nil {
		return nil, err
	}
	if leaf == nil {
		return defaultValue, nil
	}
	return leaf.valueHash, nil
}

func (smt *SMT) recursiveGet(node treeNode, depth int, path []byte) (*leafNode, error) {
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

func (smt *SMT) Update(key []byte, value []byte) error {
	path := smt.ph.Path(key)
	valueHash := smt.base().th.digest(value)
	var orphans []treeNode
	tree, err := smt.recursiveUpdate(smt.tree, 0, path, valueHash, &orphans)
	if err != nil {
		return err
	}
	smt.orphans = append(smt.orphans, persistedNodeDigests(orphans)...)
	smt.tree = tree
	return nil
}

func (smt *SMT) recursiveUpdate(
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
		// TODO (optimization) - can just count [depth:]
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

func (smt *SMT) Delete(key []byte) error {
	path := smt.ph.Path(key)
	var orphans []treeNode
	tree, err := smt.recursiveDelete(smt.tree, 0, path, &orphans)
	if err != nil {
		return err
	}
	smt.orphans = append(smt.orphans, persistedNodeDigests(orphans)...)
	smt.tree = tree
	return nil
}

func (smt *SMT) recursiveDelete(node treeNode, depth int, path []byte, orphans *[]treeNode,
) (treeNode, error) {
	node, err := smt.resolveStub(node)
	if err != nil {
		return nil, err
	}

	if node == nil {
		return nil, ErrKeyNotPresent
	}
	if leaf, ok := node.(*leafNode); ok {
		if !bytes.Equal(path, leaf.path) {
			return nil, ErrKeyNotPresent
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

func (smt *SMT) Prove(key []byte) (proof SparseMerkleProof, err error) {
	path := smt.ph.Path(key)
	var siblings []treeNode
	var sib treeNode

	node := smt.tree
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
			leafData = encodeLeaf(leaf.path, leaf.valueHash)
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

func (smt *SMT) recursiveLoad(hash []byte) (treeNode, error) {
	return smt.resolve(hash, smt.recursiveLoad)
}

// resolves a stub into a cached node
func (smt *SMT) resolveStub(node treeNode) (treeNode, error) {
	stub, ok := node.(*stubNode)
	if !ok {
		return node, nil
	}
	resolver := func(hash []byte) (treeNode, error) {
		return &stubNode{hash}, nil
	}
	return smt.resolve(stub.digest, resolver)
}

func (smt *SMT) resolve(hash []byte, resolver func([]byte) (treeNode, error),
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

func (smt *SMT) Save() (err error) {
	if err = smt.recursiveSave(smt.tree, 0); err != nil {
		return
	}
	// All orphans are persisted w/ cached digests, so we don't need to check for null
	for _, hash := range smt.orphans {
		if err = smt.nodes.Delete(hash); err != nil {
			return
		}
	}
	smt.orphans = nil
	smt.savedRoot = smt.Root()
	return
}

func (smt *SMT) recursiveSave(node treeNode, depth int) error {
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

func (smt *SMT) Root() []byte {
	return smt.hashNode(smt.tree)
}

func (node *leafNode) Persisted() bool  { return node.persisted }
func (node *innerNode) Persisted() bool { return node.persisted }
func (node *stubNode) Persisted() bool  { return true }

func (node *leafNode) cachedDigest() []byte  { return node.digest }
func (node *innerNode) cachedDigest() []byte { return node.digest }
func (node *stubNode) cachedDigest() []byte  { return node.digest }

func (smt *SMT) serialize(node treeNode) (data []byte) {
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

func (smt *SMT) hashNode(node treeNode) []byte {
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
