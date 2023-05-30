package pktcntr

import (
	"github.com/cilium/ebpf"
	"github.com/cybwan/l4slb/pkg/bpf/adapter"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS pktcntr ../../../../bpf/xdp_pktcntr_kern.c -- -I../../../../bpf/headers

var (
	objs = pktcntrObjects{}
)

func Load() error {
	// Load pre-compiled programs into the kernel.
	if err := loadPktcntrObjects(&objs, nil); err != nil {
		return err
	}

	adapter.BpfAddKnownMap(adapter.PktcntrCntrsArray, objs.CntrsArray)
	adapter.BpfAddKnownMap(adapter.PktcntrCtlArray, objs.CtlArray)

	return nil
}

func Prog() *ebpf.Program {
	return objs.Pktcntr
}

func Close() {
	objs.Close()
}
