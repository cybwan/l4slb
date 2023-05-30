package balancer

import (
	"github.com/cilium/ebpf"

	"github.com/cybwan/l4slb/pkg/bpf/adapter"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS balancer ../../../../bpf/balancer_kern.c -- -I../../../../bpf/headers

var (
	objs = balancerObjects{}
)

func Load() error {
	// Load pre-compiled programs into the kernel.
	if err := loadBalancerObjects(&objs, nil); err != nil {
		return err
	}

	adapter.BpfAddKnownMap(adapter.ChRings, objs.ChRings)
	adapter.BpfAddKnownMap(adapter.CtlArray, objs.CtlArray)
	adapter.BpfAddKnownMap(adapter.FallbackCache, objs.FallbackCache)
	adapter.BpfAddKnownMap(adapter.FallbackGlru, objs.FallbackGlru)
	adapter.BpfAddKnownMap(adapter.GlobalLruMaps, objs.GlobalLruMaps)
	adapter.BpfAddKnownMap(adapter.LpmSrcV4, objs.LpmSrcV4)
	adapter.BpfAddKnownMap(adapter.LpmSrcV6, objs.LpmSrcV6)
	adapter.BpfAddKnownMap(adapter.LruMapping, objs.LruMapping)
	adapter.BpfAddKnownMap(adapter.LruMissStats, objs.LruMissStats)
	adapter.BpfAddKnownMap(adapter.LruMissStatsVip, objs.LruMissStatsVip)
	adapter.BpfAddKnownMap(adapter.Reals, objs.Reals)
	adapter.BpfAddKnownMap(adapter.RealsStats, objs.RealsStats)
	adapter.BpfAddKnownMap(adapter.ServerIdMap, objs.ServerIdMap)
	adapter.BpfAddKnownMap(adapter.Stats, objs.Stats)
	adapter.BpfAddKnownMap(adapter.VipMap, objs.VipMap)

	return nil
}

func Prog() *ebpf.Program {
	return objs.BalancerIngress
}

func Close() {
	objs.Close()
}
