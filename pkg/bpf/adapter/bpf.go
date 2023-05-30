package adapter

import (
	"fmt"
	"os"

	"github.com/cilium/ebpf"
)

type BpfMapName string

const (
	// balancer's maps
	ChRings         = BpfMapName("ChRings")
	CtlArray        = BpfMapName("CtlArray")
	FallbackCache   = BpfMapName("FallbackCache")
	FallbackGlru    = BpfMapName("FallbackGlru")
	GlobalLruMaps   = BpfMapName("GlobalLruMaps")
	LpmSrcV4        = BpfMapName("LpmSrcV4")
	LpmSrcV6        = BpfMapName("LpmSrcV6")
	LruMapping      = BpfMapName("LruMapping")
	LruMissStats    = BpfMapName("LruMissStats")
	LruMissStatsVip = BpfMapName("LruMissStatsVip")
	Reals           = BpfMapName("Reals")
	RealsStats      = BpfMapName("RealsStats")
	ServerIdMap     = BpfMapName("ServerIdMap")
	Stats           = BpfMapName("Stats")
	VipMap          = BpfMapName("VipMap")

	// healthchecking's maps
	HcCtrlMap     = BpfMapName("HcCtrlMap")
	HcRealsMap    = BpfMapName("HcRealsMap")
	HcStatsMap    = BpfMapName("HcStatsMap")
	HcKeyMap      = BpfMapName("HcKeyMap")
	HcPcktMacs    = BpfMapName("HcPcktMacs")
	HcPcktSrcsMap = BpfMapName("HcPcktSrcsMap")
	PerHckeyStats = BpfMapName("PerHckeyStats")

	// pktcntr's maps
	PktcntrCntrsArray = BpfMapName("CntrsArray")
	PktcntrCtlArray   = BpfMapName("CtlArray")

	// root's maps
	RootArray = BpfMapName("RootArray")
)

var (
	maps = make(map[BpfMapName]*ebpf.Map)
)

func BpfAddKnownMap(name BpfMapName, bpfMap *ebpf.Map) {
	maps[name] = bpfMap
}

func getMapByName(name BpfMapName) *ebpf.Map {
	return maps[name]
}

func BpfUpdateMap(name BpfMapName, key, value interface{}, flags ebpf.MapUpdateFlags) error {
	bpfMap := getMapByName(name)
	if bpfMap == nil {
		return fmt.Errorf("not found map:%s", name)
	}
	return bpfMap.Update(key, value, flags)
}

func BpfUpdateMapBatch(name BpfMapName, keys, values interface{}, count int) error {
	bpfMap := getMapByName(name)
	if bpfMap == nil {
		return fmt.Errorf("not found map:%s", name)
	}
	opts := ebpf.BatchOptions{
		ElemFlags: 0,
		Flags:     0,
	}
	numUpdated, err := bpfMap.BatchUpdate(keys, values, &opts)
	if err != nil {
		return err
	}
	if count != numUpdated {
		return fmt.Errorf("Batch update only updated: %d elements out of: %d", numUpdated, count)
	}
	return nil
}

func BpfMapLookupElement(name BpfMapName, key, valueOut interface{}) error {
	bpfMap := getMapByName(name)
	if bpfMap == nil {
		return fmt.Errorf("not found map:%s", name)
	}
	return bpfMap.Lookup(key, valueOut)
}

func BpfMapLookupElementWithFlags(name BpfMapName, key, valueOut interface{}, flags ebpf.MapLookupFlags) error {
	bpfMap := getMapByName(name)
	if bpfMap == nil {
		return fmt.Errorf("not found map:%s", name)
	}
	return bpfMap.LookupWithFlags(key, valueOut, flags)
}

func BpfMapDeleteElement(name BpfMapName, key interface{}) error {
	bpfMap := getMapByName(name)
	if bpfMap == nil {
		return fmt.Errorf("not found map:%s", name)
	}
	return bpfMap.Delete(key)
}

func BpfMapGetNextKey(name BpfMapName, key, nextKey interface{}) error {
	bpfMap := getMapByName(name)
	if bpfMap == nil {
		return fmt.Errorf("not found map:%s", name)
	}
	return bpfMap.NextKey(key, nextKey)
}

func GetPossibleCpus() (int, error) {
	possibleCPUsFileContent, err := os.ReadFile(possibleCPUsFilePath)
	if err == nil {
		cpusAmount, err := parsePossibleCPUAmountFromCPUFileFormat(string(possibleCPUsFileContent))
		if err == nil {
			return cpusAmount, nil
		}
	}
	return 0, err
}
