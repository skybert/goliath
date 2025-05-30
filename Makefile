.DEFAULT_GOAL := build

.phony: fmt vet build todo help
fmt:
	go fmt ./...
vet: fmt
	go vet ./...
static_check: vet
	~/go/bin/staticcheck ./...
build compile: static_check
	go build
build_with_debug compile_with_debug: vet
	# -m print optimization decisions
	go build -gcflags="-m"
run: goliath
	./goliath --port 8000
run_gc_debug: goliath
	GODEBUG=gctrace=1 ./goliath
todo:
	grep --line-number --recursive --include='*.go' TODO
help:
	grep -E '^\w' Makefile | cut -d: -f1 | cut -d' ' -f1 | sort
