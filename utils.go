package smt

func hasBit(key []byte, position int) int {
    if int(key[position / 8]) & (1 << (uint(position) % 8)) > 0 {
        return 1
    } else {
        return 0
    }
}
