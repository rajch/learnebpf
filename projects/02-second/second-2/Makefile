TARGET = second
BPF = $(TARGET).bpf.o

%.bpf.o: %.bpf.c
	clang -target bpf -c $< -g -O2

vmlinux.h:
	sudo bpftool btf dump id 1 format c > vmlinux.h

$(TARGET): main.c 
	clang -o $@ $< -lbpf



.PHONY: bpf
bpf: $(BPF) vmlinux.h

.PHONY: clean
clean:
	rm -f $(BPF) $(TARGET)

.PHONY: load
load:
	sudo bpftool prog load $(BPF) /sys/fs/bpf/$(TARGET) autoattach

.PHONY: unload
unload:
	sudo rm /sys/fs/bpf/$(TARGET)
