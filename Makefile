.PHONY: install_deps build install test

install_deps:
	bash ./buildscripts/install_deps.sh
	bash ./buildscripts/install_build_deps.sh

build:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > ./htek_daemon/if_bpf/vmlinux.h
	python3 ./buildscripts/buildall.py

install:
	./build/htek install-from-repo

test:
	python3 ./tests/src/main.py
