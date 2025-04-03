TARGET = second
BPF = $(TARGET).bpf.o

vmlinux.h:
	sudo bpftool btf dump id 1 format c > vmlinux.h

$(TARGET): main.c 
	clang -o $@ $< -lbpf

$(BPF): $(TARGET).bpf.c
	clang -target bpf -c $< -g -O2

.PHONY: bpf
bpf: $(BPF) vmlinux.h

.PHONY: clean
clean:
	rm -f $(BPF) $(TARGET)
