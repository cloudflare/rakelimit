package rakelimit

import (
	"fmt"
	"syscall"

	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang-9 rake ./src/rakelimit.c -- -I./include -nostdinc -O3 -Wno-address-of-packed-member

// Rakelimit holds an instance of a ratelimiter that can be applied on a socket
type Rakelimit struct {
	bpfObjects *rakeObjects
}

// New creates a new Rakelimit instance based on the specified ppsLimit
func New(conn syscall.Conn, ppsLimit uint32) (*Rakelimit, error) {
	rakelimitSpec, err := newRakeSpecs()
	if err != nil {
		return nil, fmt.Errorf("Can't get elf spec: %v", err)
	}

	// set ratelimit
	collectionSpec := rakelimitSpec.CollectionSpec()
	if err := collectionSpec.RewriteConstants(map[string]interface{}{
		"limit": floatToFixed(float64(ppsLimit)),
	}); err != nil {
		return nil, fmt.Errorf("Can't rewrite limit: %v", err)
	}

	programSpecs, err := rakelimitSpec.Load(nil)
	if err != nil {
		return nil, fmt.Errorf("Can't load BPF program: %v", err)
	}

	raw, err := conn.SyscallConn()
	if err != nil {
		return nil, fmt.Errorf("raw conn: %s", err)
	}

	var opErr error
	if err := raw.Control(func(s uintptr) {
		var domain int
		domain, opErr = unix.GetsockoptInt(int(s), unix.SOL_SOCKET, unix.SO_DOMAIN)
		if opErr != nil {
			opErr = fmt.Errorf("can't retrieve domain: %s", opErr)
			return
		}
		if domain != unix.AF_INET {
			opErr = fmt.Errorf("only IPv4 is supported")
			return
		}
		opErr = unix.SetsockoptInt(int(s), unix.SOL_SOCKET, unix.SO_ATTACH_BPF, programSpecs.ProgramProdAnchor.FD())
		if opErr != nil {
			opErr = fmt.Errorf("can't attach BPF to socket: %s", opErr)
		}
	}); err != nil {
		return nil, fmt.Errorf("can't access fd: %s", err)
	}
	if opErr != nil {
		return nil, opErr
	}

	return &Rakelimit{bpfObjects: programSpecs}, nil
}

// Close cleans up resources occupied and should be called when finished using the structure
func (rl *Rakelimit) Close() error {
	return rl.bpfObjects.Close()
}
