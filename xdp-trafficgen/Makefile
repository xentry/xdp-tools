# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

XDP_TARGETS  := xdp_trafficgen.bpf
BPF_SKEL_TARGETS := $(XDP_TARGETS)

# Don't install skeleton object files
XDP_OBJ_INSTALL :=

TOOL_NAME := xdp-trafficgen
USER_TARGETS := xdp-trafficgen
USER_SRCS := $(filter-out %.bpf.c,$(wildcard *.c))
USER_OBJS := $(USER_SRCS:.c=.o)
MAN_PAGE := xdp-trafficgen.8
EXTRA_DEPS := xdp-trafficgen.h
USER_LIBS     = -lpthread
TEST_FILE := tests/test-xdp-trafficgen.sh

include ../lib/common.mk

$(USER_TARGETS): $(USER_OBJS) $(OBJECT_LIBBPF) $(OBJECT_LIBXDP) $(LIBMK) $(LIB_OBJS) \
$(KERN_USER_H) $(EXTRA_DEPS) $(EXTRA_USER_DEPS) $(BPF_SKEL_H)
	$(QUIET_CC)$(CC) -Wall $(CFLAGS) $(CPPFLAGS) $(LDFLAGS) -o $@ \
		$(LIB_OBJS) $(USER_OBJS) $(LDLIBS)

$(USER_OBJS): %.o: %.c $(KERN_USER_H) $(EXTRA_DEPS) $(BPF_SKEL_H)
	$(QUIET_CC)$(CC) -Wall $(CFLAGS) $(CPPFLAGS) -c -o $@ $<

