package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go third third.bpf.c -- -g -O2

// Originally created manually with /go/bin/bpf2go -go-package main third third.bpf.c -- -g -O2
