package rakelimit

import (
	"errors"
	"fmt"
	"syscall"

	"github.com/cilium/ebpf"
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
		return nil, fmt.Errorf("Can't get elf spec: %v", err)
	}

	if err := spec.RewriteConstants(map[string]interface{}{
		"LIMIT": ppsLimit,
	}); err != nil {
		return nil, fmt.Errorf("Can't rewrite limit: %v", err)
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
