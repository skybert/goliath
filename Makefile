.DEFAULT_GOAL := build

.phony: fmt vet build todo
fmt:
	go fmt ./...
vet: fmt
	go vet ./...
static_check: vet
	~/go/bin/staticcheck ./...
compile build: static_check
	go build
build_with_debug: vet
	# -m print optimization decisions
	go build -gcflags="-m"
run: goliath
	./goliath
run_gc_debug: goliath
	GODEBUG=gctrace=1 ./goliath
todo:
	grep --line-number --recursive --include='*.go' TODO
