package smt

func hasBit(data []byte, position int) int {
    if int(data[position / 8]) & (1 << (uint(position) % 8)) > 0 {
        return 1
    } else {
        return 0
    }
}

func setBit(data []byte, position int) {
    n := int(data[position / 8])
    n |= (1 << (uint(position) % 8))
    data[position / 8] = byte(n)
}

func clearBit(data []byte, position int) {
    n := int(data[position / 8])
    mask := ^(1 << (uint(position) % 8))
    n &= mask
    data[position / 8] = byte(n)
}

func emptyBytes(length int) []byte {
    b := make([]byte, length)
    return b
}
