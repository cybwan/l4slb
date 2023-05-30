package root

import (
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cybwan/l4slb/pkg/bpf/adapter"
	"github.com/cybwan/l4slb/pkg/bpf/progs/balancer"
	"github.com/cybwan/l4slb/pkg/logger"
	"net"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS root ../../../../bpf/xdp_root_kern.c -- -I../../../../bpf/headers

var (
	objs = rootObjects{}

	log = logger.New("ebpf")
)

func Load() error {
	// Load pre-compiled programs into the kernel.
	if err := loadRootObjects(&objs, nil); err != nil {
		return err
	}

	adapter.BpfAddKnownMap(adapter.RootArray, objs.RootArray)

	return nil
}

func Prog() *ebpf.Program {
	return objs.XdpRoot
}

func Close() {
	objs.Close()
}

func Attach(ifaceName string) func() {
	// Look up the network interface by name.
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatal().Msgf("lookup network iface %q: %s", ifaceName, err)
	}

	// Attach the program.
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpRoot,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatal().Msgf("could not attach XDP program: %s", err)
	}

	if err = balancer.Load(); err == nil {
		key := 1
		err = objs.RootArray.Put(uint32(key), balancer.Prog())
		if err != nil {
			log.Fatal().Msgf("put root array map failed:%s", err)
		}
		log.Printf("Press Ctrl-C to exit and remove the program")
	} else {
		log.Fatal().Msgf("loading balancer objects: %s", err)
	}

	return func() {
		objs.Close()
		l.Close()
		balancer.Close()
	}
}
