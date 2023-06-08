/*
 * Copyright (C) 2011 EfficiOS Inc.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef _ERROR_H
#define _ERROR_H

#include <common/compat/errno.hpp>
#include <common/compat/time.hpp>
#include <common/format.hpp>
#include <common/macros.hpp>
#include <common/string-utils/format.hpp>

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <urcu/tls-compat.h>

#ifndef _GNU_SOURCE
#error "lttng-tools error.h needs _GNU_SOURCE"
#endif

#include <common/compat/tid.hpp>

#include <lttng/lttng-error.h>

/* Avoid conflict with Solaris <sys/regset.h> */
#if defined(ERR) && defined(__sun__)
#undef ERR
#endif

/* Stringify the expansion of a define */
#define XSTR(d) STR(d)
#define STR(s)	#s

/*
 * Contains the string of the log entry time. This is used as a thread local
 * storage so we don't race between thread and also avoid memory allocation
 * every time a log is fired.
 */
struct log_time {
	/* Format: 00:00:00.000000000 plus NULL byte. */
	char str[19];
};

extern thread_local const char *logger_thread_name;

extern int lttng_opt_quiet;
extern int lttng_opt_verbose;
extern int lttng_opt_mi;

/* Error type. */
enum lttng_error_level {
	PRINT_ERR = 0,
	PRINT_BUG = 1,
	PRINT_WARN = 2,
	PRINT_MSG = 3,
	PRINT_DBG = 4,
	PRINT_DBG2 = 5,
	PRINT_DBG3 = 6,
};

static inline bool __lttng_print_check_opt(enum lttng_error_level type)
{
	/* lttng_opt_mi and lttng_opt_quiet. */
	switch (type) {
	case PRINT_DBG3:
	case PRINT_DBG2:
	case PRINT_DBG:
	case PRINT_MSG:
		if (lttng_opt_mi) {
			return false;
		}
		/* Fall-through. */
	case PRINT_WARN:
	case PRINT_BUG:
	case PRINT_ERR:
		if (lttng_opt_quiet) {
			return false;
		}
	}

	/* lttng_opt_verbose */
	switch (type) {
	case PRINT_DBG3:
		if (lttng_opt_verbose < 3) {
			return false;
		}
		break;
	case PRINT_DBG2:
		if (lttng_opt_verbose < 2) {
			return false;
		}
		break;
	case PRINT_DBG:
		if (lttng_opt_verbose < 1) {
			return false;
		}
		break;
	case PRINT_MSG:
	case PRINT_WARN:
	case PRINT_BUG:
	case PRINT_ERR:
		break;
	}

	return true;
}

C_LINKAGE void lttng_abort_on_error(void);

static inline void __lttng_print_check_abort(enum lttng_error_level type)
{
	switch (type) {
	case PRINT_DBG3:
	case PRINT_DBG2:
	case PRINT_DBG:
	case PRINT_MSG:
	case PRINT_WARN:
		break;
	case PRINT_BUG:
	case PRINT_ERR:
		lttng_abort_on_error();
	}
}

/*
 * Macro for printing message depending on command line option and verbosity.
 *
 * Machine interface:
 * We use lttng_opt_mi to suppress all normal msg to stdout. We don't
 * want any nested msg to show up when printing mi to stdout(if it's the case).
 * All warnings and errors should be printed to stderr as normal.
 */
#define __lttng_print(type, fmt, args...)                                            \
	do {                                                                         \
		if (__lttng_print_check_opt(type)) {                                 \
			fprintf((type) == PRINT_MSG ? stdout : stderr, fmt, ##args); \
		}                                                                    \
		__lttng_print_check_abort(type);                                     \
	} while (0)

/* Three level of debug. Use -v, -vv or -vvv for the levels */
#define _ERRMSG(msg, type, fmt, args...)                                                  \
	do {                                                                              \
		if (caa_unlikely(__lttng_print_check_opt(type))) {                        \
			char generic_name[MAX_INT_DEC_LEN(long) + MAX_INT_DEC_LEN(long)]; \
                                                                                          \
			snprintf(generic_name,                                            \
				 sizeof(generic_name),                                    \
				 "%ld/%ld",                                               \
				 (long) getpid(),                                         \
				 (long) lttng_gettid());                                  \
                                                                                          \
			__lttng_print(type,                                               \
				      msg " - %s [%s]: " fmt " (in %s() at " __FILE__     \
					  ":" XSTR(__LINE__) ")\n",                       \
				      log_add_time(),                                     \
				      logger_thread_name ?: generic_name,                 \
				      ##args,                                             \
				      __func__);                                          \
		}                                                                         \
	} while (0)

#define _ERRMSG_NO_LOC(msg, type, fmt, args...)                                           \
	do {                                                                              \
		if (caa_unlikely(__lttng_print_check_opt(type))) {                        \
			char generic_name[MAX_INT_DEC_LEN(long) + MAX_INT_DEC_LEN(long)]; \
                                                                                          \
			snprintf(generic_name,                                            \
				 sizeof(generic_name),                                    \
				 "%ld/%ld",                                               \
				 (long) getpid(),                                         \
				 (long) lttng_gettid());                                  \
                                                                                          \
			__lttng_print(type,                                               \
				      msg " - %s [%s]: " fmt "\n",                        \
				      log_add_time(),                                     \
				      logger_thread_name ?: generic_name,                 \
				      ##args);                                            \
		}                                                                         \
	} while (0)

#define MSG(fmt, args...)  __lttng_print(PRINT_MSG, fmt "\n", ##args)
#define _MSG(fmt, args...) __lttng_print(PRINT_MSG, fmt, ##args)
#define ERR(fmt, args...)  __lttng_print(PRINT_ERR, "Error: " fmt "\n", ##args)
#define WARN(fmt, args...) __lttng_print(PRINT_WARN, "Warning: " fmt "\n", ##args)

#define BUG(fmt, args...) _ERRMSG("BUG", PRINT_BUG, fmt, ##args)

#define DBG(fmt, args...)	 _ERRMSG("DBG1", PRINT_DBG, fmt, ##args)
#define DBG_NO_LOC(fmt, args...) _ERRMSG_NO_LOC("DBG1", PRINT_DBG, fmt, ##args)
#define DBG2(fmt, args...)	 _ERRMSG("DBG2", PRINT_DBG2, fmt, ##args)
#define DBG3(fmt, args...)	 _ERRMSG("DBG3", PRINT_DBG3, fmt, ##args)
#define LOG(type, fmt, args...)            \
	do {                               \
		switch (type) {            \
		case PRINT_ERR:            \
			ERR(fmt, ##args);  \
			break;             \
		case PRINT_WARN:           \
			WARN(fmt, ##args); \
			break;             \
		case PRINT_BUG:            \
			BUG(fmt, ##args);  \
			break;             \
		case PRINT_MSG:            \
			MSG(fmt, ##args);  \
			break;             \
		case PRINT_DBG:            \
			DBG(fmt, ##args);  \
			break;             \
		case PRINT_DBG2:           \
			DBG2(fmt, ##args); \
			break;             \
		case PRINT_DBG3:           \
			DBG3(fmt, ##args); \
			break;             \
		default:                   \
			abort();           \
		}                          \
	} while (0);

#define _PERROR(fmt, args...) _ERRMSG("PERROR", PRINT_ERR, fmt, ##args)

#if !defined(__GLIBC__) || \
	((_POSIX_C_SOURCE >= 200112L || _XOPEN_SOURCE >= 600) && !defined(_GNU_SOURCE))

/*
 * Version using XSI strerror_r.
 */
#define PERROR(call, args...)                                        \
	do {                                                         \
		char _perror_buf[200];                               \
		strerror_r(errno, _perror_buf, sizeof(_perror_buf)); \
		_PERROR(call ": %s", ##args, _perror_buf);           \
	} while (0);
#else
/*
 * Version using GNU strerror_r, for linux with appropriate defines.
 */
#define PERROR(call, args...)                                                      \
	do {                                                                       \
		char *_perror_buf;                                                 \
		char _perror_tmp[200];                                             \
		_perror_buf = strerror_r(errno, _perror_tmp, sizeof(_perror_tmp)); \
		_PERROR(call ": %s", ##args, _perror_buf);                         \
	} while (0);
#endif

const char *error_get_str(int32_t code);

namespace lttng {
namespace logging {
namespace details {
[[noreturn]] void die_formatting_exception(const char *format,
					   const std::exception& formatting_exception);
} /* namespace details */
} /* namespace logging */
} /* namespace lttng */

#define DBG_FMT(format_str, args...)                                                              \
	do {                                                                                      \
		try {                                                                             \
			DBG("%s", lttng::format(format_str, ##args).c_str());                     \
		} catch (const std::exception& _formatting_exception) {                           \
			lttng::logging::details::die_formatting_exception(format_str,             \
									  _formatting_exception); \
		}                                                                                 \
	} while (0);

#define WARN_FMT(format_str, args...)                                                             \
	do {                                                                                      \
		try {                                                                             \
			WARN("%s", lttng::format(format_str, ##args).c_str());                    \
		} catch (const std::exception& _formatting_exception) {                           \
			lttng::logging::details::die_formatting_exception(format_str,             \
									  _formatting_exception); \
		}                                                                                 \
	} while (0);

#define ERR_FMT(format_str, args...)                                                              \
	do {                                                                                      \
		try {                                                                             \
			ERR("%s", lttng::format(format_str, ##args).c_str());                     \
		} catch (const std::exception& _formatting_exception) {                           \
			lttng::logging::details::die_formatting_exception(format_str,             \
									  _formatting_exception); \
		}                                                                                 \
	} while (0);

/*
 * Function that format the time and return the reference of log_time.str to
 * the caller. On error, an empty string is returned thus no time will be
 * printed in the log.
 */
const char *log_add_time();

/* Name must be a statically-allocated string. */
void logger_set_thread_name(const char *name, bool set_pthread_name);

#endif /* _ERROR_H */
