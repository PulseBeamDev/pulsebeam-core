JS := js

echo:
	$(MAKE) -C $(JS) echo

build:
	$(MAKE) -C $(JS) build

test:
	$(MAKE) -C $(JS) test

publish:
	$(MAKE) -C $(JS) publish

install:
	$(MAKE) -C $(JS) install
