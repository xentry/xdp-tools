/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __UTIL_H
#define __UTIL_H

#include <bpf/libbpf.h>
#include <xdp/libxdp.h>
#include "params.h"

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif
#define STRERR_BUFSIZE 1024
#define _textify(x) #x
#define textify(x) _textify(x)

#define __unused __attribute__((unused))

#ifndef BPF_DIR_MNT
#define BPF_DIR_MNT "/sys/fs/bpf"
#endif

#ifndef BPF_OBJECT_PATH
#define BPF_OBJECT_PATH "/usr/lib/bpf"
#endif

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(*(x)))

#define FOR_EACH_MAP_KEY(_err, _map_fd, _map_key, _prev_key)                \
	for (_err = bpf_map_get_next_key(_map_fd, NULL, &_map_key);         \
             !_err;                                                         \
	     _prev_key = _map_key,                                          \
	    _err = bpf_map_get_next_key(_map_fd, &_prev_key, &_map_key))

#define min(x, y) ((x) < (y) ? x : y)
#define max(x, y) ((x) > (y) ? x : y)

#ifndef offsetof
#define offsetof(type, member) ((size_t) & ((type *)0)->member)
#endif

#ifndef container_of
#define container_of(ptr, type, member)                            \
	({                                                         \
		const typeof(((type *)0)->member) *__mptr = (ptr); \
		(type *)((char *)__mptr - offsetof(type, member)); \
	})
#endif

#ifndef roundup
#define roundup(x, y)                            \
	({                                       \
		typeof(y) __y = y;               \
		(((x) + (__y - 1)) / __y) * __y; \
	})
#endif

int try_snprintf(char *buf, size_t buf_len, const char *format, ...);

int check_bpf_environ(void);

int get_bpf_root_dir(char *buf, size_t buf_len, const char *subdir, bool fatal);

const char *get_libbpf_version(void);
int iface_get_xdp_feature_flags(int ifindex, __u64 *feature_flags);


#endif
