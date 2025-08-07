# SPDX-License-Identifier: GPL-2.0
# Top level Makefile for xdp-tools

ifeq ("$(origin V)", "command line")
VERBOSE = $(V)
endif
ifndef VERBOSE
VERBOSE = 0
endif

ifeq ($(VERBOSE),0)
MAKEFLAGS += --no-print-directory
endif

include version.mk

ifneq ($(wildcard config.mk),)
include config.mk
else
ifeq (,$(filter config.mk,$(MAKECMDGOALS)))
$(error config.mk is missing. Please run ./configure and ensure required prerequisites are installed)
endif
endif

UTILS := xdp-trafficgen

.PHONY: help clobber distclean clean install test libxdp $(UTILS) xdp-trafficgen_install

all: $(UTILS)

libxdp: config.mk
	@echo; echo libxdp; $(MAKE) -C libxdp

libxdp_install: libxdp
	@$(MAKE) -C libxdp install

$(UTILS):
	@echo; echo $@; $(MAKE) -f $@.mk

help:
	@echo "Make Targets:"
	@echo " all		    - build binaries"
	@echo " clean		    - remove products of build"
	@echo " distclean	    - remove configuration and build"
	@echo " install		    - install binaries on local machine"
	@echo " test		    - run test suite"
	@echo " archive		    - create tarball of all sources"
	@echo ""
	@echo "Make Arguments:"
	@echo " V=[0|1]		    - set build verbosity level"

config.mk: configure
	sh configure

clobber:
	touch config.mk
	$(MAKE) clean
	rm -f config.mk cscope.* compile_commands.json

distclean: clobber

clean:
	@$(MAKE) -C libxdp clean
	@$(MAKE) -C util clean
	@$(MAKE) -f xdp-trafficgen.mk clean

install: all
	@$(MAKE) -C libxdp install
	@$(MAKE) -f xdp-trafficgen.mk install

xdp-trafficgen_install: xdp-trafficgen
	@$(MAKE) -f xdp-trafficgen.mk install

test: all
	@for i in libxdp; do \
echo; echo test $$i; $(MAKE) -C $$i test; \
if [ $$? -ne 0 ]; then failed="y"; fi; \
done; \
echo; echo test xdp-trafficgen; $(MAKE) -f xdp-trafficgen.mk test; \
if [ $$? -ne 0 ]; then failed="y"; fi; \
if [ ! -z $$failed ]; then exit 1; fi


archive: xdp-tools-$(TOOLS_VERSION).tar.gz

.PHONY: xdp-tools-$(TOOLS_VERSION).tar.gz
xdp-tools-$(TOOLS_VERSION).tar.gz:
	@./mkarchive.sh "$(TOOLS_VERSION)"

compile_commands.json: clean
	compiledb make V=1
