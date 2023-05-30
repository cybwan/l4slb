// Code generated by bpf2go; DO NOT EDIT.
//go:build 386 || amd64 || amd64p32 || arm || arm64 || mips64le || mips64p32le || mipsle || ppc64le || riscv64
// +build 386 amd64 amd64p32 arm arm64 mips64le mips64p32le mipsle ppc64le riscv64

package root

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

// loadRoot returns the embedded CollectionSpec for root.
func loadRoot() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_RootBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load root: %w", err)
	}

	return spec, err
}

// loadRootObjects loads root and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*rootObjects
//	*rootPrograms
//	*rootMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadRootObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadRoot()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// rootSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type rootSpecs struct {
	rootProgramSpecs
	rootMapSpecs
}

// rootSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type rootProgramSpecs struct {
	XdpRoot *ebpf.ProgramSpec `ebpf:"xdp_root"`
}

// rootMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type rootMapSpecs struct {
	RootArray *ebpf.MapSpec `ebpf:"root_array"`
}

// rootObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadRootObjects or ebpf.CollectionSpec.LoadAndAssign.
type rootObjects struct {
	rootPrograms
	rootMaps
}

func (o *rootObjects) Close() error {
	return _RootClose(
		&o.rootPrograms,
		&o.rootMaps,
	)
}

// rootMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadRootObjects or ebpf.CollectionSpec.LoadAndAssign.
type rootMaps struct {
	RootArray *ebpf.Map `ebpf:"root_array"`
}

func (m *rootMaps) Close() error {
	return _RootClose(
		m.RootArray,
	)
}

// rootPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadRootObjects or ebpf.CollectionSpec.LoadAndAssign.
type rootPrograms struct {
	XdpRoot *ebpf.Program `ebpf:"xdp_root"`
}

func (p *rootPrograms) Close() error {
	return _RootClose(
		p.XdpRoot,
	)
}

func _RootClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed root_bpfel.o
var _RootBytes []byte