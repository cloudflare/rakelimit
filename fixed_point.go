package rakelimit

import (
	"math"
)

const fractionBits = 32

func floatToFixed(f float64) uint64 {
	ret := uint64(0)
	for i := 64 - fractionBits; i >= -fractionBits; i-- {
		ret = ret << 1
		if f >= math.Pow(2, float64(i)) {
			ret |= 1
			f -= math.Pow(2, float64(i))
		}
	}
	return ret
}

func fixedToFloat(f uint64) float64 {
	ret := float64(0)
	for i := 64 - fractionBits - 1; i >= -fractionBits; i-- {
		if f&(1<<(i+fractionBits)) != 0 {
			ret += math.Pow(2, float64(i))
		}
	}
	return ret
}
