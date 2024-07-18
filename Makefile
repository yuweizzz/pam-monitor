CLANG := clang-14
CFLAGS := "-O2 -g -Wall -Werror"

CURDIR := $(shell pwd)
HEADERS := $(CURDIR)/headers

.PHONY: clean generate build

default: build

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
