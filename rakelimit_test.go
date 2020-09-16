package rakelimit

import (
	"testing"
	"time"
)

func TestLoadBPF(t *testing.T) {
	rakeLimitSpec, err := newRakeSpecs()
	if err != nil {
		t.Fatal("Can't get elf spec", err)
	}

	programSpecs, err := rakeLimitSpec.Load(nil)
	if err != nil {
		t.Fatal("Can't load program", err)
	}
	defer programSpecs.Close()

	prog := programSpecs.ProgramProdAnchor
	payload := make([]byte, 14)
	_, _, err = prog.Test(payload)
	if err != nil {
		t.Fatal(err)
	}
}

const floatBits = 32

type FixedPointTuple struct {
	k, v uint64
}

/* TestBPFFloatToFixedPoint tests the convesion of integers/floats to fixed-point on the
userspace & the bpf side to ensure both convert it in the same way */
func TestBPFFloatToFixedPoint(t *testing.T) {
	rakeLimitSpec, err := newRakeSpecs()
	if err != nil {
		t.Fatal("Can't get elf spec", err)
	}

	programSpecs, err := rakeLimitSpec.Load(nil)
	if err != nil {
		t.Fatal("Can't load program", err)
	}
	defer programSpecs.Close()

	prog := programSpecs.ProgramTestFpCmp

	lookupTable := programSpecs.MapTestSingleResult
	payload := make([]byte, 14)

	// check 20
	if err := lookupTable.Put(uint32(0), floatToFixed(27.0)); err != nil {
		t.Fatal(err)
	}

	res, _, err := prog.Test(payload)
	if err != nil {
		t.Fatal(err)
	}
	if res == 0 {
		t.Fatal("BPF was unable to compare successfully to 27")
	}

	var fp uint64
	if err := lookupTable.Lookup(uint32(0), &fp); err != nil {
		t.Fatal(err)
	}

	// check if bpf to go works
	fl := fixedToFloat(fp)
	if fl != 19 {
		t.Fatal("Expected 19, got", fl)
	}
}

func TestBPFFEwma(t *testing.T) {
	rakeLimitSpec, err := newRakeSpecs()
	if err != nil {
		t.Fatal("Can't get elf spec", err)
	}

	programSpecs, err := rakeLimitSpec.Load(nil)
	if err != nil {
		t.Fatal("Can't load program", err)
	}
	defer programSpecs.Close()

	prog := programSpecs.ProgramTestEwma

	sr := programSpecs.MapTestSingleResult

	sr.Put(uint32(0), uint64(4294967296000))
	sr.Put(uint32(1), uint64(time.Millisecond))

	payload := make([]byte, 14)

	ret, _, err := prog.Test(payload)
	if err != nil {
		t.Fatal(err)
	}
	if ret == 0 {
		t.Fatal("Unexpected return from BPF program")
	}
	var result uint64
	if err := sr.Lookup(uint32(0), &result); err != nil {
		t.Fatal(err)
	}
}
