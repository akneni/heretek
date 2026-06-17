.PHONY: install_deps build install

install_deps:
	bash ./buildscripts/install_deps.sh
	bash ./buildscripts/install_build_deps.sh

build:
	./buildscripts/buildall.py

install:
	./build/htek install-from-repo
	./build/htek init
