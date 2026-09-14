SUBDIRS := domain-extract sql-validator

# Runs the SAME target in each subdirectory, as examples/Makefile does:
# `make` builds both, `make run` runs both.
.PHONY: all run clean $(SUBDIRS)

all:
	@set -e; for d in $(SUBDIRS); do $(MAKE) -C $$d; done

run:
	@set -e; for d in $(SUBDIRS); do $(MAKE) -C $$d run; done

clean:
	@for d in $(SUBDIRS); do $(MAKE) -C $$d clean; done

$(SUBDIRS):
	$(MAKE) -C $@
