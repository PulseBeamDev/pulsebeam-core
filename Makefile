TARGET := bundler

all:
	make build
	make build TARGET=deno

build:
	wasm-pack build --target $(TARGET) --out-dir pkg-$(TARGET) --release --no-pack --weak-refs

publish: all
	npx jsr publish --allow-slow-types

install:
	curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh

test:
	deno test -A app.test.ts
	node --experimental-vm-modules --experimental-wasm-modules app.test.js
