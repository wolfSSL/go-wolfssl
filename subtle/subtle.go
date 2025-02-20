package subtle

import (
    "github.com/wolfssl/go-wolfssl/internal/binding/cgo"
)

// ConstantTimeCompare returns 1 if the two slices, x and y, have equal contents
// and 0 otherwise. The time taken is a function of the length of the slices and
// is independent of the contents.
func ConstantTimeCompare(x, y []byte) int {
    if len(x) != len(y) {
        return 0
    }
    return cgo.ConstantTimeCompare(x, y, len(x))
}

// ConstantTimeSelect returns x if v is 1 and y if v is 0.
// Its behavior is undefined if v takes any other value.
func ConstantTimeSelect(v, x, y int) int {
    return cgo.ConstantTimeSelect(v, x, y)
}

// ConstantTimeByteEq returns 1 if x == y and 0 otherwise.
func ConstantTimeByteEq(x, y uint8) int {
    return cgo.ConstantTimeByteEq(x, y)
}
