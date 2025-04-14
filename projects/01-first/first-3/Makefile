.PHONY: bpf project clean load unload
.DEFAULT_GOAL := bpf

first.bpf.o: first.bpf.c
	clang -target bpf -c $<

bpf: first.bpf.o

first: main.c 
	clang -o $@ $< -lbpf

project: first

clean:
	rm -f first.bpf.o first

load:
	sudo bpftool prog load first.bpf.o /sys/fs/bpf/first-pin autoattach

unload:
	sudo rm -f /sys/fs/bpf/first-pin