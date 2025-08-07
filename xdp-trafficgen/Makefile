# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

XDP_TARGETS  := xdp_trafficgen.bpf
BPF_SKEL_TARGETS := $(XDP_TARGETS)

# Don't install skeleton object files
XDP_OBJ_INSTALL :=

TOOL_NAME := xdp-trafficgen
USER_TARGETS := xdp-trafficgen
USER_SRCS := $(filter-out %.bpf.c,$(wildcard *.c))
USER_OBJS := $(filter-out $(USER_TARGETS:=.o),$(USER_SRCS:.c=.o))
USER_EXTRA_C := $(USER_OBJS)
MAN_PAGE := xdp-trafficgen.8
EXTRA_DEPS := xdp-trafficgen.h
USER_LIBS     = -lpthread
TEST_FILE := tests/test-xdp-trafficgen.sh

include ../lib/common.mk

$(USER_OBJS): %.o: %.c $(KERN_USER_H) $(EXTRA_DEPS) $(BPF_SKEL_H)
	$(QUIET_CC)$(CC) -Wall $(CFLAGS) $(CPPFLAGS) -c -o $@ $<

