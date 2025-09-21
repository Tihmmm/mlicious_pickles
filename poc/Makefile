GO := go

all: generate build

generate:
	$(GO) generate ./...

build:
	$(GO) build -o bin/pickle-analyzer .

run:
	sudo ./bin/pickle-analyzer -rules rules/pickle.yar

clean:
	rm -rf bin *_bpfel* internal/ebpfw/*_bpfel* bpf/*.o
