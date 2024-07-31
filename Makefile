CURDIR := $(shell pwd)
HEADERS := $(CURDIR)/headers
LINUX_HEADERS := "/usr/include/x86_64-linux-gnu/"

BPF2GO_CC := clang
BPF2GO_CFLAGS := "-O2 -g -Wall -Werror -I$(HEADERS) -I$(LINUX_HEADERS)"

GOFILE := $(shell find . -name "*.go" | xargs)

.PHONY: clean lint generate build

default: build

lint:
	gofmt -w $(GOFILE)

clean:
	find . -name "*.elf" -delete
	find . -name "*.o" -delete

generate:
	BPF2GO_CC=$(BPF2GO_CC) BPF2GO_CFLAGS=$(BPF2GO_CFLAGS) go generate  ./...

build: clean generate
	go build
