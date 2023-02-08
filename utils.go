package smt

// getPathBit gets the bit at an offset from the most significant bit
func getPathBit(data []byte, position int) int {
	if int(data[position/8])&(1<<(8-1-uint(position)%8)) > 0 {
		return 1
	}
	return 0
}

// setPathBit sets the bit at an offset from the most significant bit
func setPathBit(data []byte, position int) {
	n := int(data[position/8])
	n |= 1 << (8 - 1 - uint(position)%8)
	data[position/8] = byte(n)
}

func countSetBits(data []byte) int {
	count := 0
	for i := 0; i < len(data)*8; i++ {
		if getPathBit(data, i) == 1 {
			count++
		}
	}
	return count
}

// counts common bits in each path, starting from some position
func countCommonPrefix(data1, data2 []byte, from int) int {
	count := 0
	for i := from; i < len(data1)*8; i++ {
		if getPathBit(data1, i) == getPathBit(data2, i) {
			count++
		} else {
			break
		}
	}
	return count + from
}

// Used for verification of serialized proof data
func hashSerialization(smt *TreeSpec, data []byte) []byte {
	if isExtension(data) {
		pathBounds, path, childHash := parseExtension(data, smt.ph)
		ext := extensionNode{path: path, child: &lazyNode{childHash}}
		copy(ext.pathBounds[:], pathBounds)
		return smt.hashNode(&ext)
	} else {
		return smt.th.digest(data)
	}
}
