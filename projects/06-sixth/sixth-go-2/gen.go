package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type sixth_data sixth sixth.bpf.c -- -g -O2
