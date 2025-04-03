PROJECT = third
BPFSOURCE = $(PROJECT).bpf.c
BPFOBJECT = $(PROJECT).bpf.o
BPFSKELETON = $(PROJECT).bpf.skel.h


$(BPFOBJECT): $(BPFSOURCE) vmlinux.h
	clang -target bpf -c $< -g -O2

vmlinux.h:
	sudo bpftool btf dump id 1 format c > vmlinux.h

$(PROJECT): main.c $(BPFSKELETON)
	clang -o $@ $< -lbpf

$(BPFSKELETON): $(BPFOBJECT)
	bpftool gen skeleton $< > $@

.PHONY: bpf
bpf: $(BPFOBJECT)

.PHONY: skeleton
skeleton: $(BPFSKELETON)

.PHONY: project
project: $(PROJECT)

.PHONY: clean
clean:
	rm -f $(PROJECT) $(BPFSKELETON) $(BPFOBJECT) vmlinux.h

.PHONY: load
load:
	sudo bpftool prog load $(BPFOBJECT) /sys/fs/bpf/$(PROJECT) autoattach

.PHONY: unload
unload:
	sudo rm /sys/fs/bpf/$(PROJECT)

.PHONY: generate
generate: vmlinux.h $(BPFSKELETON)