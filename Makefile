SHELL := bash
.PHONY: all modules debug release
all: release
modules:
	bash scripts/build-modules.sh
debug: modules
	bash scripts/build-apk.sh debug
release: modules
	bash scripts/build-apk.sh release
