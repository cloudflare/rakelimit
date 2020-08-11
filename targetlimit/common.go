package targetlimit

import (
	"os"
	"syscall"

	"github.com/cilium/ebpf"
)

const SO_ATTACH_BPF = 50

type Filer interface {
	File() (f *os.File, err error)
}
type Programmer interface {
	Program() (*ebpf.Program, error)
}

func (tl *TargetLimit) EbpfLnAttach(c Filer) error {
	file, err := c.File()
	if err != nil {
		return err
	}
	fd := int(file.Fd())

	syscall.SetNonblock(fd, true)

	err = tl.EbpfFdAttach(fd)

	file.Close()
	return err
}

func (tl *TargetLimit) EbpfFdAttach(fd int) error {
	return syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, SO_ATTACH_BPF, tl.prog.FD())
}
