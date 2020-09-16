package rakelimit

import (
	"math"
	"testing"
)

func TestFloatToFixedPoint(t *testing.T) {
	x := float64(1.0 / 7.0)
	y := fixedToFloat(floatToFixed(x))
	if math.Abs(y-x) > 0.000000001 {
		t.Fatal("Difference too large", x, y)
	}
}
