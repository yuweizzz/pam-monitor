CLANG := clang-14
CFLAGS := "-O2 -g -Wall -Werror"

CURDIR := $(shell pwd)
HEADERS := $(CURDIR)/headers

GOFILE := $(shell find . -name "*.go" | xargs)

.PHONY: clean lint generate build

default: build

lint:
	gofmt -w $(GOFILE)

clean:
	find . -name "*.elf" -delete
	find . -name "*.o" -delete

generate:
	BPF_CLANG=$(CLANG)
	BPF_CFLAGS=$(CFLAGS)
	BPF_HEADERS=$(HEADERS)
	go generate  ./...

build: clean generate
	go build
