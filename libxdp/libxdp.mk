LIBXDP_VERSION := $(shell sed -ne "/LIBXDP_[0-9\.]\+ {/ {s/LIBXDP_\([0-9\.]\+\) {/\1/;p;}" $(LIBXDP_DIR)/libxdp.map | tail -n 1)
LIBXDP_MAJOR_VERSION := $(shell echo $(LIBXDP_VERSION) | sed 's/\..*//')
