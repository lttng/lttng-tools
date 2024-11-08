/*
 * Copyright (C) 2011 EfficiOS Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#define _LGPL_SOURCE
#include "../command.hpp"
#include "../exception.hpp"
#include "../utils.hpp"

#include <common/exception.hpp>
#include <common/file-descriptor.hpp>
#include <common/mi-lttng.hpp>
#include <common/scope-exit.hpp>
#include <common/sessiond-comm/sessiond-comm.hpp>
#include <common/utils.hpp>

#include <lttng/domain-internal.hpp>

#include <fcntl.h>
#include <popt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/statvfs.h>
#include <sys/sysmacros.h>
#include <sys/types.h>

enum {
	OPT_HELP = 1,
	OPT_LIST_OPTIONS,
	OPT_ENABLE_GLOB,
	OPT_ALL,
};

namespace {
struct mi_writer *writer;

#ifdef LTTNG_EMBED_HELP
const char help_msg[] =
#include <lttng-start.1.h>
	;
#endif

struct poptOption long_options[] = {
	/* longName, shortName, argInfo, argPtr, value, descrip, argDesc */
	{ "help", 'h', POPT_ARG_NONE, nullptr, OPT_HELP, nullptr, nullptr },
	{ "list-options", 0, POPT_ARG_NONE, nullptr, OPT_LIST_OPTIONS, nullptr, nullptr },
	{ "glob", 'g', POPT_ARG_NONE, nullptr, OPT_ENABLE_GLOB, nullptr, nullptr },
	{ "all", 'a', POPT_ARG_NONE, nullptr, OPT_ALL, nullptr, nullptr },
	{ nullptr, 0, 0, nullptr, 0, nullptr, nullptr }
};

int mi_print_session(const char *session_name, int enabled)
{
	int ret;

	/* Open session element */
	ret = mi_lttng_writer_open_element(writer, config_element_session);
	if (ret) {
		goto end;
	}

	/* Print session name element */
	ret = mi_lttng_writer_write_element_string(writer, config_element_name, session_name);
	if (ret) {
		goto end;
	}

	ret = mi_lttng_writer_write_element_bool(writer, config_element_enabled, enabled);
	if (ret) {
		goto end;
	}

	/* Close session element */
	ret = mi_lttng_writer_close_element(writer);

end:
	return ret;
}

namespace {
unsigned long estimate_session_minimum_shm_size(const struct lttng_session *session)
{
	unsigned long est_min_size{ 0 };
	int domain_count{ 0 };
	int ncpus{ 0 };

	ncpus = utils_get_cpu_count(); /* Throws on error */
	auto domains = [&session, &domain_count]() {
		struct lttng_domain *raw_domains = nullptr;
		domain_count = lttng_list_domains(session->name, &raw_domains);
		if (domain_count < 0) {
			LTTNG_THROW_ERROR(lttng::format("Failed to list domains for session '%s'",
							session->name));
		}
		return lttng::make_unique_wrapper<struct lttng_domain, lttng::memory::free>(
			raw_domains);
	}();

	for (auto domain_x = 0; domain_x < domain_count; domain_x++) {
		switch (domains.get()[domain_x].type) {
		case LTTNG_DOMAIN_UST:
		case LTTNG_DOMAIN_JUL:
		case LTTNG_DOMAIN_LOG4J:
		case LTTNG_DOMAIN_PYTHON:
		case LTTNG_DOMAIN_LOG4J2:
			break;
		default:
			DBG("Domain %d not supported for shm estimation",
			    domains.get()[domain_x].type);
			continue;
		}
		auto handle = [&session, &domains, domain_x] {
			struct lttng_handle *raw_handle = nullptr;
			raw_handle = lttng_create_handle(session->name, &domains.get()[domain_x]);
			if (!raw_handle) {
				LTTNG_THROW_ERROR(
					lttng::format("Failed to get lttng handle for session '%s'",
						      session->name));
			}
			return lttng::make_unique_wrapper<struct lttng_handle, lttng_destroy_handle>(
				raw_handle);
		}();

		int channel_count{ 0 };
		auto channels = [&handle, &session, &channel_count] {
			struct lttng_channel *raw_channels = nullptr;
			channel_count = lttng_list_channels(handle.get(), &raw_channels);
			if (channel_count < 0) {
				LTTNG_THROW_ERROR(lttng::format(
					"Failed to list channels for session '%s'", session->name));
			}
			return lttng::make_unique_wrapper<struct lttng_channel, lttng::memory::free>(
				raw_channels);
		}();

		for (int channel_x = 0; channel_x < channel_count; channel_x++) {
			auto channel = &channels.get()[channel_x];
			/*
			 * This assumes per-uid or per-pid buffers with a minimum of one uid
			 * or pid.
			 */
			est_min_size += ((ncpus + session->snapshot_mode) *
					 channel->attr.num_subbuf * channel->attr.subbuf_size);
		}
	}

	return est_min_size;
}

void warn_on_small_client_shm(const char *session_name)
{
	constexpr const char *CLIENT_SHM_TEST_PATH = "/lttng-client-fake";
	const auto session_spec =
		lttng::cli::session_spec(lttng::cli::session_spec::type::NAME, session_name);
	const auto sessions = lttng::cli::list_sessions(session_spec);

	if (sessions.size() != 1) {
		LTTNG_THROW_ERROR(lttng::format("No sessions found for name '{}'", session_name));
	}

	const char *shm_path{};
	unsigned long estimated_size{ 0 };
	unsigned long memfd_device_size{ 0 };
	auto ret = lttng_get_session_shm_path_override(&sessions[0], &shm_path);
	if (ret == LTTNG_GET_SESSION_SHM_PATH_STATUS_INVALID_PARAMETER) {
		LTTNG_THROW_ERROR(
			lttng::format("Failed to get session '{}' shm path, return code: {}",
				      session_name,
				      int(ret)));
	}

	struct statvfs statbuf;
	if (ret == LTTNG_GET_SESSION_SHM_PATH_STATUS_OK) {
		/* Have to turn the shm_path into parent, since it doesn't yet exist. */
		const auto path = std::string{ shm_path };
		const auto parent = path.substr(0, path.find_last_of('/'));
		DBG("Session '%s' shm_path is set to '%s', using parent '%s'",
		    session_name,
		    shm_path,
		    parent.c_str());
		if (statvfs(parent.c_str(), &statbuf) != 0) {
			LTTNG_THROW_POSIX(
				lttng::format(
					"Failed to get the capacity of the filesystem at path '{}'",
					parent.c_str()),
				errno);
		}
	} else {
		/*
		 * The shm_path is whatever gets used by the OS when opening
		 * an anonymous shm fd. POSIX doesn't provide an introspection
		 * into it.
		 */
		auto fd = [CLIENT_SHM_TEST_PATH]() {
			int raw_fd = shm_open(CLIENT_SHM_TEST_PATH, O_RDWR | O_CREAT, 0700);
			if (raw_fd < 0) {
				LTTNG_THROW_POSIX(
					lttng::format("Failed to open shared memory at path '%s'",
						      CLIENT_SHM_TEST_PATH),
					errno);
			}
			return lttng::file_descriptor(raw_fd);
		}();

		const auto scope_shm_unlink = lttng::make_scope_exit(
			[CLIENT_SHM_TEST_PATH]() noexcept { shm_unlink(CLIENT_SHM_TEST_PATH); });
		if (fstatvfs(fd.fd(), &statbuf) != 0) {
			LTTNG_THROW_POSIX(
				"Failed to get the capacity of the filesystem at the default location used by shm_open",
				errno);
		}
	}

	memfd_device_size = statbuf.f_frsize * statbuf.f_blocks;
	DBG("memfd device id `%lu` has size %lu bytes", statbuf.f_fsid, memfd_device_size);
	estimated_size = estimate_session_minimum_shm_size(&sessions[0]);
	DBG("Estimated min shm for session '%s': %lu", session_name, estimated_size);
	if (estimated_size >= memfd_device_size) {
		WARN_FMT(
			"The estimated minimum shared memory size for all non-kernel channels of session '{}' is greater than the total shared memory allocated to {} ({}MiB >= {}MiB). Tracing for this session may not record events due to allocation failures.",
			session_name,
			ret == LTTNG_GET_SESSION_SHM_PATH_STATUS_OK ?
				shm_path :
				"the default shared memory location",
			estimated_size / 1024 / 1024,
			memfd_device_size / 1024 / 1024);
	}
}
} /* namespace */

/*
 *  start_tracing
 *
 *  Start tracing for all trace of the session.
 */
cmd_error_code start_tracing(const char *session_name)
{
	if (session_name == nullptr) {
		return CMD_ERROR;
	}

	try {
		warn_on_small_client_shm(session_name);
	} catch (const lttng::runtime_error& ex) {
		DBG("Failed to check client shm size warning: %s", ex.what());
	}

	DBG("Starting tracing for session `%s`", session_name);
	const int ret = lttng_start_tracing(session_name);
	if (ret < 0) {
		LTTNG_THROW_CTL(lttng::format("Failed to start session `{}`", session_name),
				static_cast<lttng_error_code>(-ret));
	}

	MSG("Tracing started for session `%s`", session_name);
	if (lttng_opt_mi) {
		if (mi_print_session(session_name, 1)) {
			return CMD_ERROR;
		}
	}

	return CMD_SUCCESS;
}

cmd_error_code start_tracing(const lttng::cli::session_spec& spec)
{
	bool had_warning = false;
	bool had_error = false;
	bool listing_failed = false;

	const auto sessions = [&listing_failed, &spec]() -> lttng::cli::session_list {
		try {
			return list_sessions(spec);
		} catch (const lttng::ctl::error& ctl_exception) {
			ERR_FMT("Failed to list sessions ({})",
				lttng_strerror(-ctl_exception.code()));
			listing_failed = true;
			return {};
		} catch (const lttng::cli::no_default_session_error& cli_exception) {
			/*
			 * The retrieval of the default session name already logs
			 * an error when it fails. There is no value in printing
			 * anything about this exception.
			 */
			listing_failed = true;
			return {};
		}
	}();

	if (!listing_failed && sessions.size() == 0 &&
	    spec.type_ == lttng::cli::session_spec::type::NAME) {
		ERR_FMT("Session `{}` not found", spec.value);
		return CMD_ERROR;
	}

	if (listing_failed) {
		return CMD_FATAL;
	}

	for (const auto& session : sessions) {
		cmd_error_code sub_ret;

		try {
			sub_ret = start_tracing(session.name);
		} catch (const lttng::ctl::error& ctl_exception) {
			switch (ctl_exception.code()) {
			case LTTNG_ERR_TRACE_ALREADY_STARTED:
				WARN_FMT("Tracing already started for session `{}`", session.name);
				sub_ret = CMD_SUCCESS;
				break;
			case LTTNG_ERR_NO_SESSION:
				if (spec.type_ != lttng::cli::session_spec::type::NAME) {
					/* Session destroyed during command, ignore and carry-on. */
					sub_ret = CMD_SUCCESS;
					break;
				} else {
					sub_ret = CMD_ERROR;
					break;
				}
			case LTTNG_ERR_NO_SESSIOND:
				/* Don't keep going on a fatal error. */
				return CMD_FATAL;
			default:
				/* Generic error. */
				sub_ret = CMD_ERROR;
				ERR_FMT("Failed to start session `{}` ({})",
					session.name,
					lttng_strerror(-ctl_exception.code()));
				break;
			}
		}

		/* Keep going, but report the most serious state. */
		had_warning |= sub_ret == CMD_WARNING;
		had_error |= sub_ret == CMD_ERROR;
	}

	if (had_error) {
		return CMD_ERROR;
	} else if (had_warning) {
		return CMD_WARNING;
	} else {
		return CMD_SUCCESS;
	}
}
} /* namespace */

/*
 *  cmd_start
 *
 *  The 'start <options>' first level command
 */
int cmd_start(int argc, const char **argv)
{
	int opt;
	cmd_error_code command_ret = CMD_SUCCESS;
	bool success = true;
	static poptContext pc;
	const char *leftover = nullptr;
	lttng::cli::session_spec session_spec(lttng::cli::session_spec::type::NAME);

	pc = poptGetContext(nullptr, argc, argv, long_options, 0);
	poptReadDefaultConfig(pc, 0);

	while ((opt = poptGetNextOpt(pc)) != -1) {
		switch (opt) {
		case OPT_HELP:
		{
			int ret;

			SHOW_HELP();
			command_ret = static_cast<cmd_error_code>(ret);
			goto end;
		}
		case OPT_LIST_OPTIONS:
			list_cmd_options(stdout, long_options);
			goto end;
		case OPT_ENABLE_GLOB:
			session_spec.type_ = lttng::cli::session_spec::type::GLOB_PATTERN;
			break;
		case OPT_ALL:
			session_spec.type_ = lttng::cli::session_spec::type::ALL;
			break;
		default:
			command_ret = CMD_UNDEFINED;
			goto end;
		}
	}

	session_spec.value = poptGetArg(pc);

	leftover = poptGetArg(pc);
	if (leftover) {
		ERR("Unknown argument: %s", leftover);
		command_ret = CMD_ERROR;
		goto end;
	}

	/* Mi check */
	if (lttng_opt_mi) {
		writer = mi_lttng_writer_create(fileno(stdout), lttng_opt_mi);
		if (!writer) {
			command_ret = CMD_ERROR;
			goto end;
		}

		/* Open command element */
		if (mi_lttng_writer_command_open(writer, mi_lttng_element_command_start)) {
			command_ret = CMD_ERROR;
			goto end;
		}
		/* Open output element */
		if (mi_lttng_writer_open_element(writer, mi_lttng_element_command_output)) {
			command_ret = CMD_ERROR;
			goto end;
		}

		/*
		 * Open sessions element
		 * For validation purpose
		 */
		if (mi_lttng_writer_open_element(writer, config_element_sessions)) {
			command_ret = CMD_ERROR;
			goto end;
		}
	}

	command_ret = start_tracing(session_spec);
	if (command_ret != CMD_SUCCESS) {
		success = false;
	}

	/* Mi closing */
	if (lttng_opt_mi) {
		/* Close  sessions and output element */
		if (mi_lttng_close_multi_element(writer, 2)) {
			command_ret = CMD_ERROR;
			goto end;
		}

		/* Success ? */
		if (mi_lttng_writer_write_element_bool(
			    writer, mi_lttng_element_command_success, success)) {
			command_ret = CMD_ERROR;
			goto end;
		}

		/* Command element close */
		if (mi_lttng_writer_command_close(writer)) {
			command_ret = CMD_ERROR;
			goto end;
		}
	}

end:
	/* Mi clean-up */
	if (writer && mi_lttng_writer_destroy(writer)) {
		command_ret = CMD_ERROR;
	}

	poptFreeContext(pc);
	return command_ret;
}
