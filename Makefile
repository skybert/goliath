.DEFAULT_GOAL := build

.phony: fmt vet build
fmt:
	go fmt ./...
vet: fmt
	go vet ./...
build: vet
	go build
build_with_debug: vet
	# -m print optimization decisions
	go build -gcflags="-m"
run: goliath
	./goliath
run_gc_debug: goliath
	GODEBUG=gctrace=1 ./goliath
