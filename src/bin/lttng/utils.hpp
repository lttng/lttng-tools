/*
 * Copyright (C) 2011 EfficiOS Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef _LTTNG_UTILS_H
#define _LTTNG_UTILS_H

#include <common/argpar/argpar.h>
#include <common/container-wrapper.hpp>
#include <common/dynamic-array.hpp>
#include <common/make-unique-wrapper.hpp>

#include <lttng/lttng.h>
#include <lttng/session-internal.hpp>

#include <iterator>
#include <memory>
#include <popt.h>

extern char *opt_relayd_path;
extern int opt_no_sessiond;
extern char *opt_sessiond_path;
extern pid_t sessiond_pid;

struct cmd_struct;

namespace lttng {
namespace cli {

struct session_spec {
	enum class type {
		NAME,
		GLOB_PATTERN,
		ALL,
	};

	explicit session_spec(type spec_type, const char *name_or_pattern = nullptr) noexcept :
		type_(spec_type), value(name_or_pattern)
	{
	}

	/* Disambiguate type enum from the member for buggy g++ versions. */
	type type_;
	const char *value;
};

class session_list;

namespace details {
class session_storage {
public:
	session_storage(lttng_session *raw_sessions, std::size_t sessions_count) :
		_array(raw_sessions), _count(sessions_count)
	{
	}

	session_storage(session_storage&& original) :
		_array(std::move(original._array)), _count(original._count)
	{
	}

	session_storage(session_storage&& original, std::size_t new_count) :
		_array(std::move(original._array)), _count(new_count)
	{
	}

	lttng_session_uptr _array = nullptr;
	std::size_t _count = 0;
};

class session_list_operations {
public:
	static lttng_session& get(const lttng::cli::details::session_storage& storage,
				  std::size_t index) noexcept
	{
		return storage._array[index];
	}

	static std::size_t size(const lttng::cli::details::session_storage& storage)
	{
		return storage._count;
	}
};
} /* namespace details */

/*
 * We don't use a std::vector here because it would make a copy of the C array.
 */
class session_list
	: public lttng::utils::random_access_container_wrapper<details::session_storage,
							       lttng_session&,
							       details::session_list_operations> {
public:
	friend details::session_list_operations;

	session_list() :
		lttng::utils::random_access_container_wrapper<details::session_storage,
							      lttng_session&,
							      details::session_list_operations>(
			{ nullptr, 0 })
	{
	}

	session_list(session_list&& original) :
		lttng::utils::random_access_container_wrapper<details::session_storage,
							      lttng_session&,
							      details::session_list_operations>(
			std::move(original._container))
	{
	}

	session_list(session_list&& original, std::size_t new_count) :
		lttng::utils::random_access_container_wrapper<details::session_storage,
							      lttng_session&,
							      details::session_list_operations>(
			{ std::move(original._container), new_count })
	{
	}

	session_list(lttng_session *raw_sessions, std::size_t raw_sessions_count) :
		lttng::utils::random_access_container_wrapper<details::session_storage,
							      lttng_session&,
							      details::session_list_operations>(
			{ raw_sessions, raw_sessions_count })
	{
	}

	void resize(std::size_t new_size) noexcept
	{
		_container._count = new_size;
	}
};

lttng::cli::session_list list_sessions(const struct session_spec& spec);
} /* namespace cli */
} /* namespace lttng */

char *get_session_name(void);
char *get_session_name_quiet(void);
void list_commands(struct cmd_struct *commands, FILE *ofp);
void list_cmd_options(FILE *ofp, struct poptOption *options);
void list_cmd_options_argpar(FILE *ofp, const struct argpar_opt_descr *options);

/*
 * Return the minimum order for which x <= (1UL << order).
 * Return -1 if x is 0.
 */
int get_count_order_u32(uint32_t x);

/*
 * Return the minimum order for which x <= (1UL << order).
 * Return -1 if x is 0.
 */
int get_count_order_u64(uint64_t x);

/*
 * Return the minimum order for which x <= (1UL << order).
 * Return -1 if x is 0.
 */
int get_count_order_ulong(unsigned long x);

const char *get_event_type_str(enum lttng_event_type event_type);

int print_missing_or_multiple_domains(unsigned int domain_count, bool include_agent_domains);

int spawn_relayd(const char *pathname, int port);
int check_relayd(void);
void print_session_stats(const char *session_name);
int get_session_stats_str(const char *session_name, char **str);
int show_cmd_help(const char *cmd_name, const char *help_msg);

int print_trace_archive_location(const struct lttng_trace_archive_location *location,
				 const char *session_name);

int validate_exclusion_list(const char *event_name,
			    const struct lttng_dynamic_pointer_array *exclusions);

#endif /* _LTTNG_UTILS_H */
