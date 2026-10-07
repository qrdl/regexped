# Two browser examples, served together:
#   validate/   email and URL validation
#   homoglyph/  lookalike letters, invisible and text-direction characters
#               (Unicode-mode patterns)
# Each directory also builds and serves on its own.
EXAMPLES := validate homoglyph
PORT     ?= 8080

.PHONY: all run clean

all:
	@set -e; for d in $(EXAMPLES); do $(MAKE) -C $$d; done

# Serves this directory, so index.html links to both pages. It runs until you
# stop it, which is why `browser` is the last example in ../Makefile.
run: all
	@echo "Open http://localhost:$(PORT) in your browser"
	python3 -m http.server $(PORT)

clean:
	@for d in $(EXAMPLES); do $(MAKE) -C $$d clean; done
