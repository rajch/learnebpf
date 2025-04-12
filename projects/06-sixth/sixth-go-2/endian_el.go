//go:build 386 || amd64 || arm || arm64 || loong64 || mips64le || mipsle || ppc64le || riscv64

package main

import "encoding/binary"

var hostEndian = binary.BigEndian
