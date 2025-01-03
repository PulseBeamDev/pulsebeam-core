JS := js

build:
	$(MAKE) -C $(JS) build

test: build
	$(MAKE) -C $(JS) test

install:
	$(MAKE) -C $(JS) install
