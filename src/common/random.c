/*
 * Copyright (C) 2023 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#include <lttng/constant.h>

#include <common/error.h>
#include <common/hashtable/utils.h>
#include <common/random.h>
#include <common/readwrite.h>
#include <common/time.h>

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#ifdef HAVE_SYS_SYSCALL_H
#include <sys/syscall.h>
#endif

/* getrandom is available in Linux >= 3.17. */
#if defined(__linux__) && defined(SYS_getrandom) && defined(HAVE_SYS_RANDOM_H)

#include <sys/random.h>

/* A glibc wrapper is provided only for glibc >= 2.25. */
#if defined(HAVE_GETRANDOM)
/* Simply use the existing wrapper, passing the non-block flag. */
static ssize_t _call_getrandom_nonblock(char *out_data, size_t size)
{
	return getrandom(out_data, size, GRND_NONBLOCK);
}
#else
static ssize_t _call_getrandom_nonblock(char *out_data, size_t size)
{
	const int grnd_nonblock_flag = 0x1;
	long ret = syscall(SYS_getrandom, out_data, size, grnd_nonblock_flag);

	if (ret < 0) {
		errno = -ret;
		ret = -1;
	}

	return ret;
}
#endif /* defined(HAVE_GETRANDOM) */

/* Returns either with a full read or throws. */
static int getrandom_nonblock(char *out_data, size_t size)
{
	/*
	 * Since GRND_RANDOM is _not_ used, a partial read can only be caused
	 * by a signal interruption. In this case, retry.
	 */
	int ret = 0;
	ssize_t random_ret;

	do {
		random_ret = _call_getrandom_nonblock(out_data, size);
	} while ((random_ret > 0 && random_ret != size) || (random_ret == -1 && errno == EINTR));

	if (random_ret < 0) {
		PERROR("Failed to get true random data using getrandom(): size=%zu", size);
		ret = -1;
	}

	return ret;
}
#else /* defined(__linux__) && defined(SYS_getrandom) && defined(HAVE_SYS_RANDOM_H) */
static int getrandom_nonblock(char *out_data, size_t size)
{
	WARN("getrandom() is not supported by this platform");
	return -1;
}
#endif /* defined(__linux__) && defined(SYS_getrandom) && defined(HAVE_SYS_RANDOM_H) */

static int produce_pseudo_random_seed(seed_t *out_seed)
{
	int ret;
	struct timespec real_time = {};
	struct timespec monotonic_time = {};
	unsigned long hash_seed;
	char hostname[LTTNG_HOST_NAME_MAX] = {};
	unsigned long seed;
	unsigned long pid;

	ret = clock_gettime(CLOCK_REALTIME, &real_time);
	if (ret) {
		PERROR("Failed to read real time while generating pseudo-random seed");
		goto error;
	}

	ret = clock_gettime(CLOCK_MONOTONIC, &monotonic_time);
	if (ret) {
		PERROR("Failed to read monotonic time while generating pseudo-random seed");
		goto error;
	}

	ret = gethostname(hostname, sizeof(hostname));
	if (ret) {
		PERROR("Failed to get host name while generating pseudo-random seed");
		goto error;
	}

	hash_seed = (unsigned long) real_time.tv_nsec ^ (unsigned long) real_time.tv_sec ^
			(unsigned long) monotonic_time.tv_nsec ^
			(unsigned long) monotonic_time.tv_sec;
	seed = hash_key_ulong((void *) real_time.tv_sec, hash_seed);
	seed ^= hash_key_ulong((void *) real_time.tv_nsec, hash_seed);
	seed ^= hash_key_ulong((void *) monotonic_time.tv_sec, hash_seed);
	seed ^= hash_key_ulong((void *) monotonic_time.tv_nsec, hash_seed);

	pid = getpid();
	seed ^= hash_key_ulong((void *) pid, hash_seed);
	seed ^= hash_key_str(hostname, hash_seed);
	ret = 0;

	*out_seed = (seed_t) seed;
error:
	return ret;
}

static int produce_random_seed_from_urandom(seed_t *out_seed)
{
	int ret = 0, read_ret;
	const int urandom_raw_fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);

	if (urandom_raw_fd < 0) {
		PERROR("Failed to open `/dev/urandom`");
		ret = -1;
		goto end;
	}

	read_ret = lttng_read(urandom_raw_fd, out_seed, sizeof(*out_seed));
	if (read_ret != sizeof(*out_seed)) {
		PERROR("Failed to read from `/dev/urandom`: size=%zu",
				sizeof(*out_seed));
		ret = -1;
		goto end;
	}

end:
	if (urandom_raw_fd >= 0) {
		if (close(urandom_raw_fd)) {
			PERROR("Failed to close `/dev/urandom` file descriptor");
		}
	}
	return ret;
}

int lttng_produce_true_random_seed(seed_t *out_seed)
{
	return getrandom_nonblock((char *) out_seed, sizeof(*out_seed));
}

int lttng_produce_best_effort_random_seed(seed_t *out_seed)
{
	int ret;

	ret = lttng_produce_true_random_seed(out_seed);
	if (!ret) {
		goto end;
	} else {
		WARN("Failed to produce a random seed using getrandom(), falling back to pseudo-random device seed generation which will block until its pool is initialized");
	}

	ret = produce_random_seed_from_urandom(out_seed);
	if (!ret) {
		goto end;
	} else {
		WARN("Failed to produce a random seed from the urandom device");
	}

	/* Fallback to seed generation based on time and system configuration. */
	ret = produce_pseudo_random_seed(out_seed);
end:
	return ret;
}
