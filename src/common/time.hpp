/*
 * Copyright (C) 2016 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 */

#ifndef LTTNG_TIME_H
#define LTTNG_TIME_H

#include <common/compat/time.hpp>
#include <common/macros.hpp>

#include <ctime>
#include <stdbool.h>
#include <string>
#include <time.h>

#define MSEC_PER_SEC  1000ULL
#define NSEC_PER_SEC  1000000000ULL
#define NSEC_PER_MSEC 1000000ULL
#define NSEC_PER_USEC 1000ULL
#define USEC_PER_SEC  1000000ULL
#define USEC_PER_MSEC 1000ULL

#define SEC_PER_MINUTE	60ULL
#define MINUTE_PER_HOUR 60ULL

#define USEC_PER_MINUTE (USEC_PER_SEC * SEC_PER_MINUTE)
#define USEC_PER_HOURS	(USEC_PER_MINUTE * MINUTE_PER_HOUR)

#define ISO8601_STR_LEN	 sizeof("YYYYmmddTHHMMSS+HHMM")
#define DATETIME_STR_LEN sizeof("YYYYmmdd-HHMMSS")

bool locale_supports_utf8();

#define NSEC_UNIT "ns"
#define USEC_UNIT (locale_supports_utf8() ? "µs" : "us")
#define MSEC_UNIT "ms"
#define SEC_UNIT  "s"
#define MIN_UNIT  "m"
#define HR_UNIT	  "h"

/*
 * timespec_to_ms: Convert timespec to milliseconds.
 *
 * Returns 0 on success, else -1 on error. errno is set to EOVERFLOW if
 * input would overflow the output in milliseconds.
 */
int timespec_to_ms(struct timespec ts, unsigned long *ms);

/*
 * timespec_abs_diff: Absolute difference between timespec.
 */
struct timespec timespec_abs_diff(struct timespec ts_a, struct timespec ts_b);

/*
 * Format a Unix timestamp to an ISO 8601 compatible timestamp of
 * the form "YYYYmmddTHHMMSS+HHMM" in local time. `len` must >= to
 * ISO8601_STR_LEN.
 *
 * Returns 0 on success, else -1 on error.
 */
int time_to_iso8601_str(time_t time, char *str, size_t len);
namespace lttng {
namespace utils {

std::string time_to_iso8601_str(time_t time);

} /* namespace utils */
} /* namespace lttng */

int time_to_datetime_str(time_t time, char *str, size_t len);

#endif /* LTTNG_TIME_H */
