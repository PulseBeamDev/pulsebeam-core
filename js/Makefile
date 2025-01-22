ROOT_DIR := $(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))

build:
	$(MAKE) build-target WASM_PATH=$(WASM_PATH) TARGET=experimental-nodejs-module
	$(MAKE) build-target WASM_PATH=$(WASM_PATH) TARGET=deno

build-target:
	wasm-bindgen --target $(TARGET) --out-dir $(ROOT_DIR)/pkg-$(TARGET) --typescript $(WASM_PATH)
	# jsr requires explicit d.ts reference, https://github.com/jsr-io/jsr/issues/370#issuecomment-2044467118
	sed -i '1s~^~/// <reference types="./pulsebeam_core.d.ts" />\n~' $(ROOT_DIR)/pkg-$(TARGET)/pulsebeam_core.js
	sed -i '/free(): void;/d' $(ROOT_DIR)/pkg-$(TARGET)/pulsebeam_core.d.ts
	# sed -i '/^export function __/d' $(ROOT_DIR)/pkg-$(TARGET)/*.wasm.d.ts
	# sed -i '/^export const __/d' $(ROOT_DIR)/pkg-$(TARGET)/*.wasm.d.ts
	rm -f $(ROOT_DIR)/pkg-$(TARGET)/package.json

test: build
	deno test -A app.test.ts
	echo "https://github.com/rustwasm/wasm-pack/pull/1061"
	node --trace-warnings --experimental-wasm-modules app.test.mjs

doc: build
	deno doc --html ./pkg-bundler/pulsebeam_core.js
	python3 -m http.server -d docs

publish: test
	npx jsr publish --allow-slow-types

install:
	curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh

bump:
	bash bump.bash ${VERSION} 
