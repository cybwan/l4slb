package kern

import (
	"github.com/cilium/ebpf"
	"github.com/cybwan/l4slb/pkg/bpf/adapter"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS healthchecking ../../../../../bpf/healthchecking_kern.c -- -I../../../../../bpf/headers

var (
	objs = healthcheckingObjects{}
)

func Load() error {
	// Load pre-compiled programs into the kernel.
	if err := loadHealthcheckingObjects(&objs, nil); err != nil {
		return err
	}

	adapter.BpfAddKnownMap(adapter.HcCtrlMap, objs.HcCtrlMap)
	adapter.BpfAddKnownMap(adapter.HcRealsMap, objs.HcRealsMap)
	adapter.BpfAddKnownMap(adapter.HcStatsMap, objs.HcStatsMap)

	adapter.BpfAddKnownMap(adapter.HcKeyMap, objs.HcKeyMap)
	adapter.BpfAddKnownMap(adapter.HcPcktMacs, objs.HcPcktMacs)
	adapter.BpfAddKnownMap(adapter.HcPcktSrcsMap, objs.HcPcktSrcsMap)
	adapter.BpfAddKnownMap(adapter.PerHckeyStats, objs.PerHckeyStats)

	return nil
}

func Prog() *ebpf.Program {
	return objs.HealthcheckEncap
}

func Close() {
	objs.Close()
}
