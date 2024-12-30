TARGET := nodejs

all:
	make build TARGET=nodejs
	make build TARGET=deno

build:
	wasm-pack build --target $(TARGET) --out-dir pkg-$(TARGET) --release --no-pack --weak-refs

publish: all
	npx jsr publish --allow-slow-types

install:
	curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh
