// Code generated by bpf2go; DO NOT EDIT.
//go:build mips || mips64 || ppc64 || s390x

package main

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

type sixthSixthData struct {
	ReadlinePrompt [255]int8
	_              [1]byte
	Promptlen      int32
}

// loadSixth returns the embedded CollectionSpec for sixth.
func loadSixth() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_SixthBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load sixth: %w", err)
	}

	return spec, err
}

// loadSixthObjects loads sixth and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*sixthObjects
//	*sixthPrograms
//	*sixthMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadSixthObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadSixth()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// sixthSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type sixthSpecs struct {
	sixthProgramSpecs
	sixthMapSpecs
	sixthVariableSpecs
}

// sixthProgramSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type sixthProgramSpecs struct {
	Sixth *ebpf.ProgramSpec `ebpf:"sixth"`
}

// sixthMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type sixthMapSpecs struct {
	Buffer *ebpf.MapSpec `ebpf:"buffer"`
}

// sixthVariableSpecs contains global variables before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type sixthVariableSpecs struct {
	Unuseddata *ebpf.VariableSpec `ebpf:"unuseddata"`
}

// sixthObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadSixthObjects or ebpf.CollectionSpec.LoadAndAssign.
type sixthObjects struct {
	sixthPrograms
	sixthMaps
	sixthVariables
}

func (o *sixthObjects) Close() error {
	return _SixthClose(
		&o.sixthPrograms,
		&o.sixthMaps,
	)
}

// sixthMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadSixthObjects or ebpf.CollectionSpec.LoadAndAssign.
type sixthMaps struct {
	Buffer *ebpf.Map `ebpf:"buffer"`
}

func (m *sixthMaps) Close() error {
	return _SixthClose(
		m.Buffer,
	)
}

// sixthVariables contains all global variables after they have been loaded into the kernel.
//
// It can be passed to loadSixthObjects or ebpf.CollectionSpec.LoadAndAssign.
type sixthVariables struct {
	Unuseddata *ebpf.Variable `ebpf:"unuseddata"`
}

// sixthPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadSixthObjects or ebpf.CollectionSpec.LoadAndAssign.
type sixthPrograms struct {
	Sixth *ebpf.Program `ebpf:"sixth"`
}

func (p *sixthPrograms) Close() error {
	return _SixthClose(
		p.Sixth,
	)
}

func _SixthClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed sixth_bpfeb.o
var _SixthBytes []byte
