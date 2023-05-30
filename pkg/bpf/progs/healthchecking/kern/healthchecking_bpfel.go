// Code generated by bpf2go; DO NOT EDIT.
//go:build 386 || amd64 || amd64p32 || arm || arm64 || mips64le || mips64p32le || mipsle || ppc64le || riscv64
// +build 386 amd64 amd64p32 arm arm64 mips64le mips64p32le mipsle ppc64le riscv64

package kern

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

type healthcheckingHcKey struct {
	Addr  uint32
	_     [12]byte
	Port  uint16
	Proto uint8
	_     [1]byte
}

type healthcheckingHcMac struct{ Mac [6]uint8 }

type healthcheckingHcRealDefinition struct {
	Daddr uint32
	_     [12]byte
	Flags uint8
	_     [3]byte
}

type healthcheckingHcStats struct {
	PcktsProcessed uint64
	PcktsDropped   uint64
	PcktsSkipped   uint64
	PcktsTooBig    uint64
}

// loadHealthchecking returns the embedded CollectionSpec for healthchecking.
func loadHealthchecking() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_HealthcheckingBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load healthchecking: %w", err)
	}

	return spec, err
}

// loadHealthcheckingObjects loads healthchecking and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*healthcheckingObjects
//	*healthcheckingPrograms
//	*healthcheckingMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadHealthcheckingObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadHealthchecking()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// healthcheckingSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type healthcheckingSpecs struct {
	healthcheckingProgramSpecs
	healthcheckingMapSpecs
}

// healthcheckingSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type healthcheckingProgramSpecs struct {
	HealthcheckEncap *ebpf.ProgramSpec `ebpf:"healthcheck_encap"`
}

// healthcheckingMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type healthcheckingMapSpecs struct {
	HcCtrlMap     *ebpf.MapSpec `ebpf:"hc_ctrl_map"`
	HcKeyMap      *ebpf.MapSpec `ebpf:"hc_key_map"`
	HcPcktMacs    *ebpf.MapSpec `ebpf:"hc_pckt_macs"`
	HcPcktSrcsMap *ebpf.MapSpec `ebpf:"hc_pckt_srcs_map"`
	HcRealsMap    *ebpf.MapSpec `ebpf:"hc_reals_map"`
	HcStatsMap    *ebpf.MapSpec `ebpf:"hc_stats_map"`
	PerHckeyStats *ebpf.MapSpec `ebpf:"per_hckey_stats"`
}

// healthcheckingObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadHealthcheckingObjects or ebpf.CollectionSpec.LoadAndAssign.
type healthcheckingObjects struct {
	healthcheckingPrograms
	healthcheckingMaps
}

func (o *healthcheckingObjects) Close() error {
	return _HealthcheckingClose(
		&o.healthcheckingPrograms,
		&o.healthcheckingMaps,
	)
}

// healthcheckingMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadHealthcheckingObjects or ebpf.CollectionSpec.LoadAndAssign.
type healthcheckingMaps struct {
	HcCtrlMap     *ebpf.Map `ebpf:"hc_ctrl_map"`
	HcKeyMap      *ebpf.Map `ebpf:"hc_key_map"`
	HcPcktMacs    *ebpf.Map `ebpf:"hc_pckt_macs"`
	HcPcktSrcsMap *ebpf.Map `ebpf:"hc_pckt_srcs_map"`
	HcRealsMap    *ebpf.Map `ebpf:"hc_reals_map"`
	HcStatsMap    *ebpf.Map `ebpf:"hc_stats_map"`
	PerHckeyStats *ebpf.Map `ebpf:"per_hckey_stats"`
}

func (m *healthcheckingMaps) Close() error {
	return _HealthcheckingClose(
		m.HcCtrlMap,
		m.HcKeyMap,
		m.HcPcktMacs,
		m.HcPcktSrcsMap,
		m.HcRealsMap,
		m.HcStatsMap,
		m.PerHckeyStats,
	)
}

// healthcheckingPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadHealthcheckingObjects or ebpf.CollectionSpec.LoadAndAssign.
type healthcheckingPrograms struct {
	HealthcheckEncap *ebpf.Program `ebpf:"healthcheck_encap"`
}

func (p *healthcheckingPrograms) Close() error {
	return _HealthcheckingClose(
		p.HealthcheckEncap,
	)
}

func _HealthcheckingClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed healthchecking_bpfel.o
var _HealthcheckingBytes []byte
