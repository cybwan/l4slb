// Code generated by bpf2go; DO NOT EDIT.
//go:build arm64be || armbe || mips || mips64 || mips64p32 || ppc64 || s390 || s390x || sparc || sparc64
// +build arm64be armbe mips mips64 mips64p32 ppc64 s390 s390x sparc sparc64

package ipip

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

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
	HcCtrlMap  *ebpf.MapSpec `ebpf:"hc_ctrl_map"`
	HcRealsMap *ebpf.MapSpec `ebpf:"hc_reals_map"`
	HcStatsMap *ebpf.MapSpec `ebpf:"hc_stats_map"`
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
	HcCtrlMap  *ebpf.Map `ebpf:"hc_ctrl_map"`
	HcRealsMap *ebpf.Map `ebpf:"hc_reals_map"`
	HcStatsMap *ebpf.Map `ebpf:"hc_stats_map"`
}

func (m *healthcheckingMaps) Close() error {
	return _HealthcheckingClose(
		m.HcCtrlMap,
		m.HcRealsMap,
		m.HcStatsMap,
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
//go:embed healthchecking_bpfeb.o
var _HealthcheckingBytes []byte
