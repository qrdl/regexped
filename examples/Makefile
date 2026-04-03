EXAMPLES := url-ipv6 secrets url-parts browser node

.PHONY: all clean $(EXAMPLES)

all: $(EXAMPLES)

$(EXAMPLES):
	$(MAKE) -C $@

clean:
	for d in $(EXAMPLES); do $(MAKE) -C $$d clean; done
