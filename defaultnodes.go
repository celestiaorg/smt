package smt

import(
    "hash"
)

var defaultNodesMap map[hash.Hash][][]byte

func init() {
    defaultNodesMap = make(map[hash.Hash][][]byte)
}

func defaultNodes(hasher hash.Hash) [][]byte {
    nodes, ok := defaultNodesMap[hasher]

    if !ok {
        depth := hasher.Size() * 8
        defaultNodesMap[hasher] = make([][]byte, depth)
        nodes = defaultNodesMap[hasher]

        hasher.Write(defaultValue)
        bottom := hasher.Sum(nil)
        hasher.Reset()

        nodes[depth - 1] = bottom

        for i := depth - 1; i > 0; i-- {
            hasher.Write(nodePrefix)
            hasher.Write(nodes[i])
            hasher.Write(nodes[i])
            nodes[i - 1] = hasher.Sum(nil)
            hasher.Reset()
        }
    }

    return nodes
}
