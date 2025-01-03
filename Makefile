TARGET := bundler

all:
	make build
	make build TARGET=deno

build:
	wasm-pack build --target $(TARGET) --out-dir pkg-$(TARGET) --release --no-pack --weak-refs && cp js-assets/* pkg-$(TARGET)/

publish: all
	cp js-assets/README.md . && npx jsr publish --allow-slow-types && rm README.md

install:
	curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh

test:
	deno test -A app.test.ts
	echo "https://github.com/rustwasm/wasm-pack/pull/1061"
	node --experimental-vm-modules --trace-warnings --experimental-wasm-modules app.test.js
