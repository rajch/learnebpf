first: main.c 
	clang -o $@ $< -lbpf

first.bpf.o: first.bpf.c
	clang -target bpf -c $<

.PHONY: bpf
bpf: first.bpf.o

.PHONY: clean
clean:
	rm -f first.bpf.o first
