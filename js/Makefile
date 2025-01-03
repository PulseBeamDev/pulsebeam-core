TARGET := bundler

build:
	$(MAKE) build-target
	$(MAKE) build-target TARGET=deno

build-target:
	wasm-pack build --target $(TARGET) --out-dir $(PWD)/pkg-$(TARGET) --release --no-pack --weak-refs

test: build
	deno test -A app.test.ts
	echo "https://github.com/rustwasm/wasm-pack/pull/1061"
	node --experimental-vm-modules --trace-warnings --experimental-wasm-modules app.test.js

doc: build
	deno doc --html ./pkg-bundler/pulsebeam_core.js
	python3 -m http.server -d docs

publish: test
	npx jsr publish --allow-slow-types

install:
	curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh
