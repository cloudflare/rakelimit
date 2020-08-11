# [*] Go

EBPF_FILES = $(wildcard src/*.c) $(wildcard src/*.h)
BPF_CFLAGS = "-Wall -Wextra -O2 -D SIPHASH_KEY=\"$(shell openssl rand -hex 16)\" -I/usr/include/x86_64-linux-gnu"
GOBIN=$(shell which go)

targetlimit: main.go targetlimit/target_limit.c.go
	go build

targetlimit/target_limit.c.go: $(EBPF_FILES) targetlimit/target_limit.go
	cd targetlimit && BPF_CFLAGS=$(BPF_CFLAGS) go generate

# [*] Code hygiene

bench: targetlimit/target_limit.c.go
	sudo $(GOBIN) test -benchmem -bench Benchmark

.PHONY: format clean targetlimit
format:
	clang-format-7 -i src/*.c src/*.h

clean:
	rm -rf targetlimit/target_limit.c.go

