JS := js
WASM_PATH := $(PWD)/target/wasm32-unknown-unknown/release/pulsebeam_core.wasm

echo:
	$(MAKE) -C $(JS) echo

build:
	cargo build --release --target wasm32-unknown-unknown
	# wasm-opt -Os -o $(WASM_DIR)/pulsebeam_core.wasm $(WASM_DIR)/pulsebeam_core.wasm
	$(MAKE) -C $(JS) build WASM_PATH=$(WASM_PATH)

test:
	$(MAKE) -C $(JS) test WASM_PATH=$(WASM_PATH)

publish:
	$(MAKE) -C $(JS) publish

install:
	$(MAKE) -C $(JS) install
	cargo install cargo-zigbuild
	# brew install binaryen

bump:
	$(MAKE) -C $(JS) bump VERSION=$(VERSION)
