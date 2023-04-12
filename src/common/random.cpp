/*
 * Copyright (C) 2023 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#include <common/error.hpp>
#include <common/file-descriptor.hpp>
#include <common/format.hpp>
#include <common/hashtable/utils.hpp>
#include <common/random.hpp>
#include <common/readwrite.hpp>
#include <common/time.hpp>

#include <lttng/constant.h>

#include <fcntl.h>

#ifdef HAVE_SYS_SYSCALL_H
#include <sys/syscall.h>
#endif

#define LTTNG_THROW_RANDOM_PRODUCTION_ERROR(msg) \
	throw lttng::random::production_error(msg, __FILE__, __func__, __LINE__)

namespace {
/* getrandom is available in Linux >= 3.17. */
#if defined(__linux__) && defined(SYS_getrandom) && defined(HAVE_SYS_RANDOM_H)

#include <sys/random.h>

/* A glibc wrapper is provided only for glibc >= 2.25. */
#if defined(HAVE_GETRANDOM)
/* Simply use the existing wrapper, passing the non-block flag. */
ssize_t _call_getrandom_nonblock(char *out_data, std::size_t size)
{
	return getrandom(out_data, size, GRND_NONBLOCK);
}
#else
ssize_t _call_getrandom_nonblock(char *out_data, std::size_t size)
{
	const int grnd_nonblock_flag = 0x1;

	auto ret = syscall(SYS_getrandom, out_data, size, grnd_nonblock_flag);
	if (ret < 0) {
		errno = -ret;
		ret = -1;
	}

	return ret;
}
#endif /* defined(HAVE_GETRANDOM) */

/* Returns either with a full read or throws. */
void getrandom_nonblock(char *out_data, std::size_t size)
{
	/*
	 * Since GRND_RANDOM is _not_ used, a partial read can only be caused
	 * by a signal interruption. In this case, retry.
	 */
	ssize_t ret;

	do {
		ret = _call_getrandom_nonblock(out_data, size);
	} while ((ret > 0 && ret != size) || (ret == -1 && errno == EINTR));

	if (ret < 0) {
		LTTNG_THROW_POSIX(
			fmt::format("Failed to get true random data using getrandom(): size={}",
				    size),
			errno);
	}
}
#else /* defined(__linux__) && defined(SYS_getrandom) && defined(HAVE_SYS_RANDOM_H) */
__attribute__((noreturn)) void getrandom_nonblock(char *out_data __attribute__((unused)),
						  std::size_t size __attribute__((unused)))
{
	LTTNG_THROW_RANDOM_PRODUCTION_ERROR("getrandom() is not supported by this platform");
}
#endif /* defined(__linux__) && defined(SYS_getrandom) && defined(HAVE_SYS_RANDOM_H) */

lttng::random::seed_t produce_pseudo_random_seed()
{
	int ret;
	struct timespec real_time = {};
	struct timespec monotonic_time = {};
	unsigned long hash_seed;
	char hostname[LTTNG_HOST_NAME_MAX] = {};
	unsigned long seed;

	ret = clock_gettime(CLOCK_REALTIME, &real_time);
	if (ret) {
		LTTNG_THROW_POSIX("Failed to read real time while generating pseudo-random seed",
				  errno);
	}

	ret = clock_gettime(CLOCK_MONOTONIC, &monotonic_time);
	if (ret) {
		LTTNG_THROW_POSIX(
			"Failed to read monotonic time while generating pseudo-random seed", errno);
	}

	ret = gethostname(hostname, sizeof(hostname));
	if (ret) {
		LTTNG_THROW_POSIX("Failed to get host name while generating pseudo-random seed",
				  errno);
	}

	hash_seed = (unsigned long) real_time.tv_nsec ^ (unsigned long) real_time.tv_sec ^
		(unsigned long) monotonic_time.tv_nsec ^ (unsigned long) monotonic_time.tv_sec;
	seed = hash_key_ulong((void *) real_time.tv_sec, hash_seed);
	seed ^= hash_key_ulong((void *) real_time.tv_nsec, hash_seed);
	seed ^= hash_key_ulong((void *) monotonic_time.tv_sec, hash_seed);
	seed ^= hash_key_ulong((void *) monotonic_time.tv_nsec, hash_seed);

	const unsigned long pid = getpid();
	seed ^= hash_key_ulong((void *) pid, hash_seed);
	seed ^= hash_key_str(hostname, hash_seed);

	return static_cast<lttng::random::seed_t>(seed);
}

lttng::random::seed_t produce_random_seed_from_urandom()
{
	/*
	 * Open /dev/urandom as a file_descriptor, or throw on error. The
	 * lambda is used to reduce the scope of the raw fd as much as possible.
	 */
	lttng::file_descriptor urandom{ []() {
		const auto urandom_raw_fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);

		if (urandom_raw_fd < 0) {
			LTTNG_THROW_POSIX("Failed to open `/dev/urandom`", errno);
		}

		return urandom_raw_fd;
	}() };

	lttng::random::seed_t seed;
	try {
		urandom.read(&seed, sizeof(seed));
	} catch (const std::exception& e) {
		LTTNG_THROW_RANDOM_PRODUCTION_ERROR(fmt::format(
			"Failed to read from `/dev/urandom`: size={}: {}", sizeof(seed), e.what()));
	}

	return seed;
}

} /* namespace */

lttng::random::production_error::production_error(const std::string& msg,
						  const char *file_name,
						  const char *function_name,
						  unsigned int line_number) :
	lttng::runtime_error(msg, file_name, function_name, line_number)
{
}

lttng::random::seed_t lttng::random::produce_true_random_seed()
{
	lttng::random::seed_t seed;

	getrandom_nonblock(reinterpret_cast<char *>(&seed), sizeof(seed));
	return seed;
}

lttng::random::seed_t lttng::random::produce_best_effort_random_seed()
{
	try {
		return lttng::random::produce_true_random_seed();
	} catch (std::exception& e) {
		WARN("%s",
		     fmt::format(
			     "Failed to produce a random seed using getrandom(), falling back to pseudo-random device seed generation which will block until its pool is initialized: {}",
			     e.what())
			     .c_str());
	}

	try {
		/*
		 * Can fail for various reasons, including not being accessible
		 * under some containerized environments.
		 */
		produce_random_seed_from_urandom();
	} catch (std::exception& e) {
		WARN("%s",
		     fmt::format("Failed to produce a random seed from the urandom device: {}",
				 e.what())
			     .c_str());
	}

	/* Fallback to time-based seed generation. */
	return produce_pseudo_random_seed();
}
