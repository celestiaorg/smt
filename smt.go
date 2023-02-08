package smt

import (
	"bytes"
	"hash"
)

var (
	_ treeNode = (*innerNode)(nil)
	_ treeNode = (*leafNode)(nil)
)

type treeNode interface {
	Persisted() bool
	CachedDigest() []byte
}

// A branch within the tree
type innerNode struct {
	// Both child nodes are always non-nil
	leftChild, rightChild treeNode
	persisted             bool
	digest                []byte
}

// Stores data and full path
type leafNode struct {
	path      []byte
	valueHash []byte
	persisted bool
	digest    []byte
}

// A compressed chain of singly-linked inner nodes
type extensionNode struct {
	path []byte
	// Offsets into path slice of bounds defining actual path segment.
	// Note: assumes path is <=256 bits
	pathBounds [2]byte
	// Child is always an inner node, or lazy.
	child     treeNode
	persisted bool
	digest    []byte
}

// Represents an uncached, persisted node
type lazyNode struct {
	digest []byte
}

type SMT struct {
	TreeSpec
	nodes MapStore
	// Last persisted root hash
	savedRoot []byte
	// Current state of tree
	tree treeNode
	// Lists of per-operation orphan sets
	orphans []orphanNodes
}

// Hashes of persisted nodes deleted from tree
type orphanNodes = [][]byte

func NewSparseMerkleTree(nodes MapStore, hasher hash.Hash, options ...Option) *SMT {
	smt := SMT{
		TreeSpec: newTreeSpec(hasher),
		nodes:    nodes,
	}
	for _, option := range options {
		option(&smt)
	}
	return &smt
}

func ImportSparseMerkleTree(nodes MapStore, hasher hash.Hash, root []byte, options ...Option) *SMT {
	smt := NewSparseMerkleTree(nodes, hasher, options...)
	smt.tree = &lazyNode{root}
	smt.savedRoot = root
	return smt
}

func (smt *SMT) Get(key []byte) ([]byte, error) {
	path := smt.ph.Path(key)
	var leaf *leafNode
	var err error
	for node, depth := &smt.tree, 0; ; depth++ {
		*node, err = smt.resolveLazy(*node)
		if err != nil {
			return nil, err
		}
		if *node == nil {
			break
		}
		if n, ok := (*node).(*leafNode); ok {
			if bytes.Equal(path, n.path) {
				leaf = n
			}
			break
		}
		if ext, ok := (*node).(*extensionNode); ok {
			if _, match := ext.match(path, depth); !match {
				break
			}
			depth += ext.length()
			node = &ext.child
			*node, err = smt.resolveLazy(*node)
			if err != nil {
				return nil, err
			}
		}
		inner := (*node).(*innerNode)
		if getPathBit(path, depth) == left {
			node = &inner.leftChild
		} else {
			node = &inner.rightChild
		}
	}
	if leaf == nil {
		return defaultValue, nil
	}
	return leaf.valueHash, nil
}

func (smt *SMT) Update(key []byte, value []byte) error {
	path := smt.ph.Path(key)
	valueHash := smt.digestValue(value)
	var orphans orphanNodes
	tree, err := smt.update(smt.tree, 0, path, valueHash, &orphans)
	if err != nil {
		return err
	}
	smt.tree = tree
	if len(orphans) > 0 {
		smt.orphans = append(smt.orphans, orphans)
	}
	return nil
}

func (smt *SMT) update(
	node treeNode, depth int, path, value []byte, orphans *orphanNodes,
) (treeNode, error) {
	node, err := smt.resolveLazy(node)
	if err != nil {
		return node, err
	}

	newLeaf := &leafNode{path: path, valueHash: value}
	// Empty subtree is always replaced by a single leaf
	if node == nil {
		return newLeaf, nil
	}
	if leaf, ok := node.(*leafNode); ok {
		prefixlen := countCommonPrefix(path, leaf.path, depth)
		if prefixlen == smt.depth() { // replace leaf if paths are equal
			smt.addOrphan(orphans, node)
			return newLeaf, nil
		}
		// We insert an "extension" representing multiple single-branch inner nodes
		last := &node
		if depth < prefixlen {
			// note: this keeps path slice alive - GC inefficiency?
			if depth > 0xff {
				panic("invalid depth")
			}
			ext := extensionNode{path: path, pathBounds: [2]byte{byte(depth), byte(prefixlen)}}
			*last = &ext
			last = &ext.child
		}
		if getPathBit(path, prefixlen) == left {
			*last = &innerNode{leftChild: newLeaf, rightChild: leaf}
		} else {
			*last = &innerNode{leftChild: leaf, rightChild: newLeaf}
		}
		return node, nil
	}

	smt.addOrphan(orphans, node)

	if ext, ok := node.(*extensionNode); ok {
		var branch *treeNode
		node, branch, depth = ext.split(path, depth)
		*branch, err = smt.update(*branch, depth, path, value, orphans)
		if err != nil {
			return node, err
		}
		ext.setDirty()
		return node, nil
	}

	inner := node.(*innerNode)
	var child *treeNode
	if getPathBit(path, depth) == left {
		child = &inner.leftChild
	} else {
		child = &inner.rightChild
	}
	*child, err = smt.update(*child, depth+1, path, value, orphans)
	if err != nil {
		return node, err
	}
	inner.setDirty()
	return node, nil
}

func (smt *SMT) Delete(key []byte) error {
	path := smt.ph.Path(key)
	var orphans orphanNodes
	tree, err := smt.delete(smt.tree, 0, path, &orphans)
	if err != nil {
		return err
	}
	smt.tree = tree
	if len(orphans) > 0 {
		smt.orphans = append(smt.orphans, orphans)
	}
	return nil
}

func (smt *SMT) delete(node treeNode, depth int, path []byte, orphans *orphanNodes,
) (treeNode, error) {
	node, err := smt.resolveLazy(node)
	if err != nil {
		return node, err
	}

	if node == nil {
		return node, ErrKeyNotPresent
	}
	if leaf, ok := node.(*leafNode); ok {
		if !bytes.Equal(path, leaf.path) {
			return node, ErrKeyNotPresent
		}
		smt.addOrphan(orphans, node)
		return nil, nil
	}

	smt.addOrphan(orphans, node)

	if ext, ok := node.(*extensionNode); ok {
		if _, match := ext.match(path, depth); !match {
			return node, ErrKeyNotPresent
		}
		ext.child, err = smt.delete(ext.child, depth+ext.length(), path, orphans)
		if err != nil {
			return node, err
		}
		switch n := ext.child.(type) {
		case *leafNode:
			return n, nil
		case *extensionNode:
			// Join this extension with the child
			smt.addOrphan(orphans, n)
			n.pathBounds[0] = ext.pathBounds[0]
			node = n
		}
		ext.setDirty()
		return node, nil
	}

	inner := node.(*innerNode)
	var child, sib *treeNode
	if getPathBit(path, depth) == left {
		child, sib = &inner.leftChild, &inner.rightChild
	} else {
		child, sib = &inner.rightChild, &inner.leftChild
	}
	*child, err = smt.delete(*child, depth+1, path, orphans)
	if err != nil {
		return node, err
	}
	*sib, err = smt.resolveLazy(*sib)
	if err != nil {
		return node, err
	}
	// Handle replacement of this node, depending on the new child states.
	// Note that inner nodes exist at a fixed depth, and can't be moved.
	children := [2]*treeNode{child, sib}
	for i := 0; i < 2; i++ {
		if *children[i] == nil {
			switch n := (*children[1-i]).(type) {
			case *leafNode:
				return n, nil
			case *extensionNode:
				// "Absorb" this node into the extension by prepending
				smt.addOrphan(orphans, n)
				n.pathBounds[0]--
				n.setDirty()
				return n, nil
			}
		}
	}
	inner.setDirty()
	return node, nil
}

func (smt *SMT) Prove(key []byte) (proof SparseMerkleProof, err error) {
	path := smt.ph.Path(key)
	var siblings []treeNode
	var sib treeNode

	node := smt.tree
	for depth := 0; depth < smt.depth(); depth++ {
		node, err = smt.resolveLazy(node)
		if err != nil {
			return
		}
		if node == nil {
			break
		}
		if _, ok := node.(*leafNode); ok {
			break
		}
		if ext, ok := node.(*extensionNode); ok {
			length, match := ext.match(path, depth)
			if match {
				for i := 0; i < length; i++ {
					siblings = append(siblings, nil)
				}
				depth += length
				node = ext.child
				node, err = smt.resolveLazy(node)
				if err != nil {
					return
				}
			} else {
				node = ext.expand()
			}
		}
		inner := node.(*innerNode)
		if getPathBit(path, depth) == left {
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
		sibling := siblings[len(siblings)-i-1]
		sideNode = smt.hashNode(sibling)
		sideNodes = append(sideNodes, sideNode)
	}

	proof = SparseMerkleProof{
		SideNodes:             sideNodes,
		NonMembershipLeafData: leafData,
	}
	if sib != nil {
		sib, err = smt.resolveLazy(sib)
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
func (smt *SMT) resolveLazy(node treeNode) (treeNode, error) {
	stub, ok := node.(*lazyNode)
	if !ok {
		return node, nil
	}
	resolver := func(hash []byte) (treeNode, error) {
		return &lazyNode{hash}, nil
	}
	ret, err := smt.resolve(stub.digest, resolver)
	if err != nil {
		return node, err
	}
	return ret, nil
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
	if isExtension(data) {
		ext := extensionNode{persisted: true, digest: hash}
		pathBounds, path, childHash := parseExtension(data, smt.ph)
		ext.path = path
		copy(ext.pathBounds[:], pathBounds)
		ext.child, err = resolver(childHash)
		if err != nil {
			return
		}
		return &ext, nil
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

func (smt *SMT) Commit() (err error) {
	// All orphans are persisted and have cached digests, so we don't need to check for null
	for _, orphans := range smt.orphans {
		for _, hash := range orphans {
			if err = smt.nodes.Delete(hash); err != nil {
				return
			}
		}
	}
	smt.orphans = nil
	if err = smt.commit(smt.tree); err != nil {
		return
	}
	smt.savedRoot = smt.Root()
	return
}

func (smt *SMT) commit(node treeNode) error {
	if node != nil && node.Persisted() {
		return nil
	}
	switch n := node.(type) {
	case *leafNode:
		n.persisted = true
	case *innerNode:
		n.persisted = true
		if err := smt.commit(n.leftChild); err != nil {
			return err
		}
		if err := smt.commit(n.rightChild); err != nil {
			return err
		}
	case *extensionNode:
		n.persisted = true
		if err := smt.commit(n.child); err != nil {
			return err
		}
	default:
		return nil
	}
	data := smt.serialize(node)
	return smt.nodes.Set(smt.hashNode(node), data)
}

func (smt *SMT) Root() []byte {
	return smt.hashNode(smt.tree)
}

func (smt *SMT) addOrphan(orphans *[][]byte, node treeNode) {
	if node.Persisted() {
		*orphans = append(*orphans, node.CachedDigest())
	}
}

func (node *leafNode) Persisted() bool      { return node.persisted }
func (node *innerNode) Persisted() bool     { return node.persisted }
func (node *lazyNode) Persisted() bool      { return true }
func (node *extensionNode) Persisted() bool { return node.persisted }

func (node *leafNode) CachedDigest() []byte      { return node.digest }
func (node *innerNode) CachedDigest() []byte     { return node.digest }
func (node *lazyNode) CachedDigest() []byte      { return node.digest }
func (node *extensionNode) CachedDigest() []byte { return node.digest }

func (inner *innerNode) setDirty() {
	inner.persisted = false
	inner.digest = nil
}

func (ext *extensionNode) length() int { return int(ext.pathBounds[1] - ext.pathBounds[0]) }

func (ext *extensionNode) setDirty() {
	ext.persisted = false
	ext.digest = nil
}

// Returns length of matching prefix, and whether it's a full match
func (ext *extensionNode) match(path []byte, depth int) (int, bool) {
	if depth != ext.pathStart() {
		panic("depth != path_begin")
	}
	for i := ext.pathStart(); i < ext.pathEnd(); i++ {
		if getPathBit(ext.path, i) != getPathBit(path, i) {
			return i - ext.pathStart(), false
		}
	}
	return ext.length(), true
}

func (ext *extensionNode) commonPrefix(path []byte) int {
	count := 0
	for i := ext.pathStart(); i < ext.pathEnd(); i++ {
		if getPathBit(ext.path, i) != getPathBit(path, i) {
			break
		}
		count++
	}
	return count
}

func (ext *extensionNode) pathStart() int { return int(ext.pathBounds[0]) }
func (ext *extensionNode) pathEnd() int   { return int(ext.pathBounds[1]) }

// Splits the node in-place; returns replacement node, child node at the split, and split depth
func (ext *extensionNode) split(path []byte, depth int) (treeNode, *treeNode, int) {
	if depth != ext.pathStart() {
		panic("depth != path_begin")
	}
	index := ext.pathStart()
	var myBit, branchBit int
	for ; index < ext.pathEnd(); index++ {
		myBit = getPathBit(ext.path, index)
		branchBit = getPathBit(path, index)
		if myBit != branchBit {
			break
		}
	}
	if index == ext.pathEnd() {
		return ext, &ext.child, index
	}

	child := ext.child
	var branch innerNode
	var head treeNode
	var tail *treeNode
	if myBit == left {
		tail = &branch.leftChild
	} else {
		tail = &branch.rightChild
	}

	// Split at first bit: chain starts with new node
	if index == ext.pathStart() {
		head = &branch
		ext.pathBounds[0]++ // Shrink the extension from front
		if ext.length() == 0 {
			*tail = child
		} else {
			*tail = ext
		}
	} else {
		// Split inside: chain ends at index
		head = ext
		ext.child = &branch
		if index == ext.pathEnd()-1 {
			*tail = child
		} else {
			*tail = &extensionNode{
				path:       ext.path,
				pathBounds: [2]byte{byte(index + 1), ext.pathBounds[1]},
				child:      child,
			}
		}
		ext.pathBounds[1] = byte(index)
	}
	var b treeNode = &branch
	return head, &b, index
}

func (ext *extensionNode) expand() treeNode {
	last := ext.child
	for i := ext.pathEnd() - 1; i >= ext.pathStart(); i-- {
		var next innerNode
		if getPathBit(ext.path, i) == left {
			next.leftChild = last
		} else {
			next.rightChild = last
		}
		last = &next
	}
	return last
}
