.PHONY: init
init:
	go mod init xdp-drops
	go mod tidy

.PHONY: deps
deps:
	go get github.com/cilium/ebpf/cmd/bpf2go

.PHONY: gen
gen:
	go generate

.PHONY: build
build: 
	CGO_ENABLED=0 go build -o drops

.PHONY: run
run:
	sudo timeout -k 70 60 ./drops