SUBDIRS := domain-extract sql-validator

.PHONY: all run clean $(SUBDIRS)

all: $(SUBDIRS)

$(SUBDIRS):
	$(MAKE) -C $@ run

run: all

clean:
	for d in $(SUBDIRS); do $(MAKE) -C $$d clean; done
