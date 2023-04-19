/*
 * Copyright (C) 2011 EfficiOS Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef _LTTNG_UTILS_H
#define _LTTNG_UTILS_H

#include <common/argpar/argpar.h>
#include <common/dynamic-array.hpp>
#include <common/make-unique-wrapper.hpp>

#include <lttng/lttng.h>

#include <iterator>
#include <memory>
#include <popt.h>

extern char *opt_relayd_path;
extern int opt_no_sessiond;
extern char *opt_sessiond_path;
extern pid_t sessiond_pid;

struct cmd_struct;

struct session_spec {
	enum type {
		NAME,
		GLOB_PATTERN,
		ALL,
	};

	type type;
	const char *value;
};

/*
 * We don't use a std::vector here because it would make a copy of the C array.
 */
class session_list {
	template <typename ContainerType, typename DereferenceReturnType>
	class iterator_template : public std::iterator<std::random_access_iterator_tag, std::size_t> {
	public:
		explicit iterator_template(ContainerType& list, std::size_t k) : _list(list), _index(k)
		{
		}

		iterator_template& operator++() noexcept
		{
			++_index;
			return *this;
		}

		iterator_template& operator--() noexcept
		{
			--_index;
			return *this;
		}

		iterator_template& operator++(int) noexcept
		{
			_index++;
			return *this;
		}

		iterator_template& operator--(int) noexcept
		{
			_index--;
			return *this;
		}

		bool operator==(iterator_template other) const noexcept
		{
			return _index == other._index;
		}

		bool operator!=(iterator_template other) const noexcept
		{
			return !(*this == other);
		}

		DereferenceReturnType& operator*() const noexcept
		{
			return _list[_index];
		}

	private:
		ContainerType& _list;
		std::size_t _index;
	};

	using iterator = iterator_template<session_list, lttng_session>;
	using const_iterator = iterator_template<const session_list, const lttng_session>;

public:
	session_list() : _sessions_count(0), _sessions(nullptr)
	{
	}

	session_list(session_list&& original, std::size_t new_count)
	{
		_sessions_count = new_count;
		_sessions = std::move(original._sessions);
	}

	session_list(struct lttng_session *raw_sessions, std::size_t raw_sessions_count)
	{
		_sessions_count = raw_sessions_count;
		_sessions.reset(raw_sessions);
	}

	iterator begin() noexcept
	{
		return iterator(*this, 0);
	}

	iterator end() noexcept
	{
		return iterator(*this, _sessions_count);
	}

	const_iterator begin() const noexcept
	{
		return const_iterator(*this, 0);
	}

	const_iterator end() const noexcept
	{
		return const_iterator(*this, _sessions_count);
	}

	std::size_t size() const noexcept
	{
		return _sessions_count;
	}

	void resize(std::size_t new_size) noexcept
	{
		_sessions_count = new_size;
	}

	lttng_session& operator[](std::size_t index)
	{
		LTTNG_ASSERT(index < _sessions_count);
		return _sessions.get()[index];
	}

	const lttng_session& operator[](std::size_t index) const
	{
		LTTNG_ASSERT(index < _sessions_count);
		return _sessions.get()[index];
	}

private:
	std::size_t _sessions_count;
	std::unique_ptr<lttng_session,
			lttng::details::create_unique_class<lttng_session, lttng::free>>
		_sessions;
};

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

session_list list_sessions(const struct session_spec& spec);

#endif /* _LTTNG_UTILS_H */
