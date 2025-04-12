//go:build mips || mips64 || ppc64 || s390x

package main

import "encoding/binary"

var hostEndian = binary.BigEndian
