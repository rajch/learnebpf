.PHONY: clean load unload

first.bpf.o: first.bpf.c
	clang -target bpf -c $<

clean:
	rm -f first.bpf.o

load:
	sudo bpftool prog load first.bpf.o /sys/fs/bpf/first-pin autoattach

unload:
	sudo rm -f /sys/fs/bpf/first-pin
