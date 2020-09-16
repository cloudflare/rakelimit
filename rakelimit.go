package rakelimit

import (
	"fmt"
	"os"
	"syscall"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang-9 rake ./src/rakelimit.c -- -I./src -I./include -I./include/bpf -I./include/linux -nostdinc -O3 -Wno-address-of-packed-member

// Rakelimit holds an instance of a ratelimiter that can be applied on a socket
type Rakelimit struct {
	bpfObjects *rakeObjects
}

// NewRakelimit creates a new Rakelimit instance based on the specified ppsLimit
func NewRakelimit(ppsLimit float64) (*Rakelimit, error) {
	var rakelimit Rakelimit
	rakelimitSpec, err := newRakeSpecs()
	if err != nil {
		return nil, fmt.Errorf("Can't get elf spec: %v", err)
	}

	// set ratelimit
	collectionSpec := rakelimitSpec.CollectionSpec()
	if err := collectionSpec.RewriteConstants(map[string]interface{}{
		"limit": floatToFixed(ppsLimit),
	}); err != nil {
		return nil, fmt.Errorf("Can't rewrite limit: %v", err)
	}

	programSpecs, err := rakelimitSpec.Load(nil)
	if err != nil {
		return nil, fmt.Errorf("Can't load BPF program: %v", err)
	}

	rakelimit.bpfObjects = programSpecs
	return &rakelimit, nil
}

// SoAttachBPF defines the parameter for setsockopt to attach a bpf program
const SoAttachBPF = 50

// Attach enables the rate limiter on a socket, which it expects as a File pointer
func (rl *Rakelimit) Attach(f *os.File) error {
	fd := int(f.Fd())
	syscall.SetNonblock(fd, true)
	if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, SoAttachBPF, rl.bpfObjects.ProgramProdAnchor.FD()); err != nil {
		return fmt.Errorf("Can't attach bpf program to socket: %v", err)
	}
	return nil
}

// GetDropStatsPerLevel gets the amount of packet drops
// that occured on the given level, identified by the index in the result
func (rl *Rakelimit) GetDropStatsPerLevel() ([]int64, error) {
	return nil, nil
}

// Close cleans up resources occupied and should be called when finished using the structure
func (rl *Rakelimit) Close() error {
	return rl.bpfObjects.Close()
}
