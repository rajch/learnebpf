.PHONY: bpf bpfcore project projectcore skeleton clean load unload
.DEFAULT_GOAL: bpf

PROJECT = sixth
BPFHEADERS = sixth.h
PROJECTHEADERS = 

BPFSOURCE = $(PROJECT).bpf.c
BPFOBJECT = $(PROJECT).bpf.o
BPFSKELETON = $(PROJECT).bpf.skel.h

bpf: $(BPFOBJECT)

bpfcore: vmlinux.h $(BPFOBJECT) 

project: $(PROJECT)

projectcore: vmlinux.h $(BPFSKELETON) $(PROJECT)

skeleton: $(BPFSKELETON)

clean:
	rm -f $(PROJECT) $(BPFSKELETON) $(BPFOBJECT) vmlinux.h

load:
	sudo bpftool prog load $(BPFOBJECT) /sys/fs/bpf/$(PROJECT) autoattach

.PHONY: unload
unload:
	sudo rm /sys/fs/bpf/$(PROJECT)


$(BPFOBJECT): $(BPFSOURCE) $(BPFHEADERS)
	clang -target bpf -c $< -g -O2

vmlinux.h:
	sudo bpftool btf dump id 1 format c > vmlinux.h

$(PROJECT): main.c $(BPFHEADERS) $(PROJECTHEADERS)
	clang -o $@ $< -lbpf

$(BPFSKELETON): $(BPFOBJECT)
	bpftool gen skeleton $< > $@
