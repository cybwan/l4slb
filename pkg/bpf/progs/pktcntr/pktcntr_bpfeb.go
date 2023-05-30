// Code generated by bpf2go; DO NOT EDIT.
//go:build arm64be || armbe || mips || mips64 || mips64p32 || ppc64 || s390 || s390x || sparc || sparc64
// +build arm64be armbe mips mips64 mips64p32 ppc64 s390 s390x sparc sparc64

package pktcntr

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

// loadPktcntr returns the embedded CollectionSpec for pktcntr.
func loadPktcntr() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_PktcntrBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load pktcntr: %w", err)
	}

	return spec, err
}

// loadPktcntrObjects loads pktcntr and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*pktcntrObjects
//	*pktcntrPrograms
//	*pktcntrMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadPktcntrObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadPktcntr()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// pktcntrSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type pktcntrSpecs struct {
	pktcntrProgramSpecs
	pktcntrMapSpecs
}

// pktcntrSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type pktcntrProgramSpecs struct {
	Pktcntr *ebpf.ProgramSpec `ebpf:"pktcntr"`
}

// pktcntrMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type pktcntrMapSpecs struct {
	CntrsArray *ebpf.MapSpec `ebpf:"cntrs_array"`
	CtlArray   *ebpf.MapSpec `ebpf:"ctl_array"`
}

// pktcntrObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadPktcntrObjects or ebpf.CollectionSpec.LoadAndAssign.
type pktcntrObjects struct {
	pktcntrPrograms
	pktcntrMaps
}

func (o *pktcntrObjects) Close() error {
	return _PktcntrClose(
		&o.pktcntrPrograms,
		&o.pktcntrMaps,
	)
}

// pktcntrMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadPktcntrObjects or ebpf.CollectionSpec.LoadAndAssign.
type pktcntrMaps struct {
	CntrsArray *ebpf.Map `ebpf:"cntrs_array"`
	CtlArray   *ebpf.Map `ebpf:"ctl_array"`
}

func (m *pktcntrMaps) Close() error {
	return _PktcntrClose(
		m.CntrsArray,
		m.CtlArray,
	)
}

// pktcntrPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadPktcntrObjects or ebpf.CollectionSpec.LoadAndAssign.
type pktcntrPrograms struct {
	Pktcntr *ebpf.Program `ebpf:"pktcntr"`
}

func (p *pktcntrPrograms) Close() error {
	return _PktcntrClose(
		p.Pktcntr,
	)
}

func _PktcntrClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed pktcntr_bpfeb.o
var _PktcntrBytes []byte