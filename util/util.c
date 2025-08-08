/* SPDX-License-Identifier: GPL-2.0 */

#define _GNU_SOURCE

#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/file.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <sys/vfs.h>
#include <sys/stat.h>
#include <linux/if_link.h> /* Need XDP flags */
#include <linux/magic.h> /* BPF FS magic */
#include <linux/err.h> /* ERR_PTR */
#include <bpf/bpf.h>
#include <dirent.h>
#include <net/if.h>

#include "util.h"
#include "logging.h"

int try_snprintf(char *buf, size_t buf_len, const char *format, ...)
{
	va_list args;
	int len;

	va_start(args, format);
	len = vsnprintf(buf, buf_len, format, args);
	va_end(args);

	if (len < 0)
		return -EINVAL;
	else if ((size_t)len >= buf_len)
		return -ENAMETOOLONG;

	return 0;
}

static int set_rlimit(unsigned int min_limit)
{
	struct rlimit limit;
	int err = 0;

	err = getrlimit(RLIMIT_MEMLOCK, &limit);
	if (err) {
		err = -errno;
		pr_warn("Couldn't get current rlimit\n");
		return err;
	}

	if (limit.rlim_cur == RLIM_INFINITY || limit.rlim_cur == 0) {
		pr_debug("Current rlimit is infinity or 0. Not raising\n");
		return -ENOMEM;
	}

	if (min_limit) {
		if (limit.rlim_cur >= min_limit) {
			pr_debug("Current rlimit %ju already >= minimum %u\n",
				 (uintmax_t)limit.rlim_cur, min_limit);
			return 0;
		}
		pr_debug("Setting rlimit to minimum %u\n", min_limit);
		limit.rlim_cur = min_limit;
	} else {
		pr_debug("Doubling current rlimit of %ju\n", (uintmax_t)limit.rlim_cur);
		limit.rlim_cur <<= 1;
	}
	limit.rlim_max = max(limit.rlim_cur, limit.rlim_max);

	err = setrlimit(RLIMIT_MEMLOCK, &limit);
	if (err) {
		err = -errno;
		pr_warn("Couldn't raise rlimit: %s\n", strerror(-err));
		return err;
	}

	return 0;
}

static const char *_libbpf_compile_version = LIBBPF_VERSION;
static char _libbpf_version[10] = {};

const char *get_libbpf_version(void)
{
	/* Start by copying compile-time version into buffer so we have a
	 * fallback value in case we are dynamically linked, or can't find a
	 * version in /proc/self/maps below.
	 */
	strncpy(_libbpf_version, _libbpf_compile_version,
		sizeof(_libbpf_version)-1);

#ifdef LIBBPF_DYNAMIC
	char path[PATH_MAX], buf[PATH_MAX], *s;
	bool found = false;
	FILE *fp;

	/* When dynamically linking against libbpf, we can't be sure that the
	 * version we discovered at compile time is actually the one we are
	 * using at runtime. This can lead to hard-to-debug errors, so we try to
	 * discover the correct version at runtime.
	 *
	 * The simple solution to this would be if libbpf itself exported a
	 * version in its API. But since it doesn't, we work around this by
	 * parsing the mappings of the binary at runtime, looking for the full
	 * filename of libbpf.so and using that.
	 */
	fp = fopen("/proc/self/maps", "r");
	if (fp == NULL)
		goto out;

	while ((s = fgets(buf, sizeof(buf), fp)) != NULL) {
		/* We are looking for a line like:
		 * 7f63c2105000-7f63c2106000 rw-p 00032000 fe:02 4200947                    /usr/lib/libbpf.so.0.1.0
		 */
		if (sscanf(s, "%*x-%*x %*4c %*x %*5c %*d %s\n", path) == 1 &&
		    (s = strstr(path, "libbpf.so.")) != NULL) {
			strncpy(_libbpf_version, s+10, sizeof(_libbpf_version)-1);
			found = true;
			break;
		}
	}

	fclose(fp);
out:
	if (!found)
		pr_warn("Couldn't find runtime libbpf version - falling back to compile-time value!\n");

#endif
	_libbpf_version[sizeof(_libbpf_version)-1] = '\0';
	return _libbpf_version;
}

static bool bpf_is_valid_mntpt(const char *mnt, unsigned long magic)
{
	struct statfs st_fs;

	if (statfs(mnt, &st_fs) < 0)
		return false;
	if ((unsigned long)st_fs.f_type != magic)
		return false;

	return true;
}

static const char *bpf_find_mntpt_single(unsigned long magic, char *mnt,
					 int len, const char *mntpt)
{
	if (bpf_is_valid_mntpt(mntpt, magic)) {
		strncpy(mnt, mntpt, len - 1);
		mnt[len - 1] = '\0';
		return mnt;
	}

	return NULL;
}

static const char *bpf_find_mntpt(const char *fstype, unsigned long magic,
				  char *mnt, int len,
				  const char * const *known_mnts)
{
	const char * const *ptr;
	char type[100];
	FILE *fp;

	if (known_mnts) {
		ptr = known_mnts;
		while (*ptr) {
			if (bpf_find_mntpt_single(magic, mnt, len, *ptr))
				return mnt;
			ptr++;
		}
	}

	if (len != PATH_MAX)
		return NULL;

	fp = fopen("/proc/mounts", "r");
	if (fp == NULL)
		return NULL;

	while (fscanf(fp, "%*s %" textify(PATH_MAX) "s %99s %*s %*d %*d\n", mnt,
		      type) == 2) {
		if (strcmp(type, fstype) == 0)
			break;
	}

	fclose(fp);
	if (strcmp(type, fstype) != 0)
		return NULL;

	return mnt;
}

static int bpf_mnt_check_target(const char *target)
{
	int ret;

	ret = mkdir(target, S_IRWXU);
	if (ret && errno != EEXIST) {
		ret = -errno;
		pr_warn("mkdir %s failed: %s\n", target, strerror(-ret));
		return ret;
	}

	return 0;
}
/* simplified version of code from iproute2 */
static const char *bpf_get_work_dir()
{
	static char bpf_tmp[PATH_MAX] = BPF_DIR_MNT;
	static char bpf_wrk_dir[PATH_MAX];
	static const char *mnt;
	static bool bpf_mnt_cached;
	static const char *const bpf_known_mnts[] = {
		BPF_DIR_MNT,
		"/bpf",
		0,
	};
	int ret;

	if (bpf_mnt_cached)
		return mnt;

	mnt = bpf_find_mntpt("bpf", BPF_FS_MAGIC, bpf_tmp, sizeof(bpf_tmp),
			     bpf_known_mnts);
	if (!mnt) {
		mnt = BPF_DIR_MNT;
		ret = bpf_mnt_check_target(mnt);
		if (ret || !bpf_is_valid_mntpt(mnt, BPF_FS_MAGIC)) {
			mnt = NULL;
			goto out;
		}
	}

	strncpy(bpf_wrk_dir, mnt, sizeof(bpf_wrk_dir));
	bpf_wrk_dir[sizeof(bpf_wrk_dir) - 1] = '\0';
	mnt = bpf_wrk_dir;
out:
	bpf_mnt_cached = true;
	return mnt;
}

int get_bpf_root_dir(char *buf, size_t buf_len, const char *subdir, bool fatal)
{
	const char *bpf_dir;

	bpf_dir = bpf_get_work_dir();
	if (!bpf_dir) {
		logging_print(fatal ? LOG_WARN : LOG_DEBUG,
			      "Could not find BPF working dir - bpffs not mounted?\n");
		return -ENOENT;
	}

	if (subdir)
		return try_snprintf(buf, buf_len, "%s/%s", bpf_dir, subdir);
	else
		return try_snprintf(buf, buf_len, "%s", bpf_dir);
}



int check_bpf_environ(void)
{
	init_lib_logging();

	if (geteuid() != 0) {
		pr_warn("This program must be run as root.\n");
		return 1;
	}

	/* Try to avoid probing errors due to rlimit exhaustion by starting out
	 * with an rlimit of 1 MiB. This is not going to solve all issues, but
	 * it will at least make things work when there is nothing else loaded.
	 *
	 * Ignore return code because an error shouldn't abort running.
	 */
	set_rlimit(1024 * 1024);

	return 0;
}



int iface_get_xdp_feature_flags(int ifindex, __u64 *feature_flags)
{
#ifdef HAVE_LIBBPF_BPF_XDP_QUERY
	LIBBPF_OPTS(bpf_xdp_query_opts, opts);
	int err;

	err = bpf_xdp_query(ifindex, 0, &opts);
	if (err)
		return err;

	*feature_flags = opts.feature_flags;
	return 0;
#else
	return -EOPNOTSUPP;
#endif

}
