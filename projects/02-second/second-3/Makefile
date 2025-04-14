.PHONY: bpf project skeleton clean load unload
.DEFAULT_GOAL := bpf

PROJECT = second

$(PROJECT).bpf.o: $(PROJECT).bpf.c vmlinux.h
	clang -target bpf -g -O2 -c $<

bpf: $(PROJECT).bpf.o

vmlinux.h:
	sudo bpftool btf dump id 1 format c > vmlinux.h

$(PROJECT): main.c $(PROJECT).bpf.skel.h 
	clang -o $@ $< -lbpf

project: $(PROJECT)

$(PROJECT).bpf.skel.h: $(PROJECT).bpf.o
	bpftool gen skeleton $< > $@

skeleton: $(PROJECT).bpf.skel.h

clean:
	rm -f $(PROJECT).bpf.o vmlinux.h $(PROJECT).bpf.skel.h $(PROJECT)

load:
	sudo bpftool prog load $(PROJECT).bpf.o /sys/fs/bpf/$(PROJECT)-pin autoattach

unload:
	sudo rm -f /sys/fs/bpf/$(PROJECT)-pin
