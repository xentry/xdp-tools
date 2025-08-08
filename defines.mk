ROOT_DIR := $(patsubst %/,%,$(dir $(abspath $(lastword $(MAKEFILE_LIST)))))

CFLAGS ?= -O2 -g
BPF_CFLAGS ?= -Wall -Wno-unused-value -Wno-pointer-sign \
              -Wno-compare-distinct-pointer-types \
              -Wno-visibility -Werror -fno-stack-protector
BPF_TARGET ?= bpf

HAVE_FEATURES :=

include $(ROOT_DIR)/config.mk
include $(ROOT_DIR)/version.mk

PREFIX ?= /usr/local
LIBDIR ?= $(PREFIX)/lib
SBINDIR ?= $(PREFIX)/sbin
HDRDIR ?= $(PREFIX)/include/xdp
DATADIR ?= $(PREFIX)/share
RUNDIR ?= /run
MANDIR ?= $(DATADIR)/man
SCRIPTSDIR ?= $(DATADIR)/xdp-tools
BPF_DIR_MNT ?= /sys/fs/bpf
BPF_OBJECT_DIR ?= $(LIBDIR)/bpf
MAX_DISPATCHER_ACTIONS ?= 10

HEADER_DIR := $(ROOT_DIR)/headers
TEST_DIR := $(ROOT_DIR)/tests
LIBXDP_DIR ?= $(ROOT_DIR)/libxdp
UTIL_DIR := $(ROOT_DIR)/util

DEFINES := -DBPF_DIR_MNT=\"$(BPF_DIR_MNT)\" -DBPF_OBJECT_PATH=\"$(BPF_OBJECT_DIR)\" \
        -DMAX_DISPATCHER_ACTIONS=$(MAX_DISPATCHER_ACTIONS) -DTOOLS_VERSION=\"$(TOOLS_VERSION)\" \
        -DLIBBPF_VERSION=\"$(LIBBPF_VERSION)\" -DRUNDIR=\"$(RUNDIR)\"

DEFINES += $(foreach feat,$(HAVE_FEATURES),-DHAVE_$(feat))

ifneq ($(PRODUCTION),1)
DEFINES += -DDEBUG
endif

ifeq ($(SYSTEM_LIBBPF),y)
DEFINES += -DLIBBPF_DYNAMIC
endif

DEFINES += -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64

CFLAGS += -std=gnu11 -Wextra -Werror $(DEFINES) $(ARCH_INCLUDES)
BPF_CFLAGS += $(DEFINES) $(filter -ffile-prefix-map=%,$(CFLAGS)) $(filter -I%,$(CFLAGS)) $(ARCH_INCLUDES)

CONFIGMK := $(ROOT_DIR)/config.mk
LIBMK := Makefile $(CONFIGMK) $(ROOT_DIR)/defines.mk $(ROOT_DIR)/common.mk $(ROOT_DIR)/version.mk
