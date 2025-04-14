.PHONY: bpf project clean load unload
.DEFAULT_GOAL := bpf

PROJECT = second

$(PROJECT).bpf.o: $(PROJECT).bpf.c vmlinux.h
	clang -target bpf -g -O2 -c $<

bpf: $(PROJECT).bpf.o

vmlinux.h:
	sudo bpftool btf dump id 1 format c > vmlinux.h

$(PROJECT): main.c 
	clang -o $@ $< -lbpf

project: $(PROJECT)

clean:
	rm -f $(PROJECT).bpf.o vmlinux.h $(PROJECT)

load:
	sudo bpftool prog load $(PROJECT).bpf.o /sys/fs/bpf/$(PROJECT)-pin autoattach

unload:
	sudo rm -f /sys/fs/bpf/$(PROJECT)-pin
