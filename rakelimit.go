package rakelimit

import (
	"errors"
	"fmt"
	"math"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang-9 rake ./src/rakelimit.c -- -I./include -nostdinc -O3 -Wno-address-of-packed-member

// Rakelimit holds an instance of a ratelimiter that can be applied on a socket
type Rakelimit struct {
	domain     int
	program    *ebpf.Program
	bpfObjects *rakeObjects
}

// New creates a new Rakelimit instance based on the specified ppsLimit
func New(conn syscall.Conn, ppsLimit uint32) (*Rakelimit, error) {
	// set ratelimit
	spec, err := loadRake()
	if err != nil {
		return nil, fmt.Errorf("get elf spec: %v", err)
	}

	if err := rewriteConstant(spec, "LIMIT", uint64(ppsLimit)); err != nil {
		return nil, err
	}

	var objs rakeObjects
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		return nil, fmt.Errorf("load BPF: %v", err)
	}

	raw, err := conn.SyscallConn()
	if err != nil {
		return nil, fmt.Errorf("raw conn: %s", err)
	}

	var opErr error
	var domain int
	var prog *ebpf.Program
	if err := raw.Control(func(s uintptr) {
		domain, opErr = unix.GetsockoptInt(int(s), unix.SOL_SOCKET, unix.SO_DOMAIN)
		if opErr != nil {
			opErr = fmt.Errorf("can't retrieve domain: %s", opErr)
			return
		}

		switch domain {
		case unix.AF_INET:
			prog = objs.FilterIpv4
		case unix.AF_INET6:
			prog = objs.FilterIpv6
		default:
			opErr = fmt.Errorf("unsupported socket domain: %d", domain)
			return
		}

		opErr = unix.SetsockoptInt(int(s), unix.SOL_SOCKET, unix.SO_ATTACH_BPF, prog.FD())
		if errors.Is(opErr, unix.ENOMEM) {
			opErr = fmt.Errorf("attach filter: net.core.optmem_max might be too low: %s", opErr)
			return
		}
		if opErr != nil {
			opErr = fmt.Errorf("attach filter: %s", opErr)
		}
	}); err != nil {
		return nil, fmt.Errorf("can't access fd: %s", err)
	}
	if opErr != nil {
		return nil, opErr
	}

	return &Rakelimit{domain, prog, &objs}, nil
}

// Close cleans up resources occupied and should be called when finished using the structure
func (rl *Rakelimit) Close() error {
	return rl.bpfObjects.Close()
}

func rewriteConstant(spec *ebpf.CollectionSpec, symbol string, value uint64) error {
	if value == math.MaxUint32 {
		// Not useable due to a bug in cilium/ebpf.
		return fmt.Errorf("value exceeds maximum")
	}

	rewritten := false
	for name, prog := range spec.Programs {
		for i := range prog.Instructions {
			ins := &prog.Instructions[i]
			if ins.Reference != symbol {
				continue
			}

			if !ins.IsConstantLoad(asm.DWord) {
				return fmt.Errorf("program %s: instruction %d: not a dword-sized constant load: %s", name, i, ins)
			}

			ins.Constant = int64(value)
			rewritten = true
		}
	}

	if !rewritten {
		return fmt.Errorf("symbol %s is not referenced", symbol)
	}

	return nil
}
