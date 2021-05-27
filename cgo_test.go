// +build cgo,cgotest

package rakelimit

import (
	"encoding/hex"
	"testing"
)

func TestFasthash64(t *testing.T) {
	golden := []struct {
		input []byte
		hash  uint64
	}{
		{[]byte("asdefg"), 0x07ffd15db88b150b},
		{[]byte("Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua."), 0xbb1655682c0ac75d},
	}

	for _, gold := range golden {
		have := fasthash64(gold.input)
		if have != gold.hash {
			t.Logf("\n%s", hex.Dump(gold.input))
			t.Errorf("Expected hash %016x, got %016x", gold.hash, have)
		}
	}
}
