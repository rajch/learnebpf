.PHONY: project clean
PROJECT = sixth
BPF_SKELETONS = $(PROJECT)_bpfeb.go $(PROJECT)_bpfel.go
BPF_SOURCES = sixth.bpf.c sixth.h vmlinux.h
OUTPUT = $(PROJECT)-go

$(BPF_SKELETONS): $(BPF_SOURCES) gen.go
	go generate

$(OUTPUT): $(BPF_SKELETONS) main.go
	go build

project: $(OUTPUT)

clean:
	rm -f $(BPF_SKELETONS) $(OUTPUT)
