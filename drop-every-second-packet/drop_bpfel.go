// Code generated by bpf2go; DO NOT EDIT.
//go:build (386 || amd64 || arm || arm64 || loong64 || mips64le || mipsle || ppc64le || riscv64) && linux

package main

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

// loadDrop returns the embedded CollectionSpec for drop.
func loadDrop() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_DropBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load drop: %w", err)
	}

	return spec, err
}

// loadDropObjects loads drop and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*dropObjects
//	*dropPrograms
//	*dropMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadDropObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadDrop()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// dropSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type dropSpecs struct {
	dropProgramSpecs
	dropMapSpecs
	dropVariableSpecs
}

// dropProgramSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type dropProgramSpecs struct {
	XdpDrops2nd *ebpf.ProgramSpec `ebpf:"xdp_drops_2nd"`
}

// dropMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type dropMapSpecs struct {
	PerfMap *ebpf.MapSpec `ebpf:"perf_map"`
}

// dropVariableSpecs contains global variables before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type dropVariableSpecs struct {
}

// dropObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadDropObjects or ebpf.CollectionSpec.LoadAndAssign.
type dropObjects struct {
	dropPrograms
	dropMaps
	dropVariables
}

func (o *dropObjects) Close() error {
	return _DropClose(
		&o.dropPrograms,
		&o.dropMaps,
	)
}

// dropMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadDropObjects or ebpf.CollectionSpec.LoadAndAssign.
type dropMaps struct {
	PerfMap *ebpf.Map `ebpf:"perf_map"`
}

func (m *dropMaps) Close() error {
	return _DropClose(
		m.PerfMap,
	)
}

// dropVariables contains all global variables after they have been loaded into the kernel.
//
// It can be passed to loadDropObjects or ebpf.CollectionSpec.LoadAndAssign.
type dropVariables struct {
}

// dropPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadDropObjects or ebpf.CollectionSpec.LoadAndAssign.
type dropPrograms struct {
	XdpDrops2nd *ebpf.Program `ebpf:"xdp_drops_2nd"`
}

func (p *dropPrograms) Close() error {
	return _DropClose(
		p.XdpDrops2nd,
	)
}

func _DropClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed drop_bpfel.o
var _DropBytes []byte
