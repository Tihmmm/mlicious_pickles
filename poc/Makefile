GO := go

all: generate build

generate:
	$(GO) generate ./...

build:
	$(GO) build -o bin/pickle-analyzer .

run:
	sudo ./bin/pickle-analyzer -yara rules/pickle.yar

clean:
	rm -rf bin PickleTrace_bpfel_* bpf/*.o
