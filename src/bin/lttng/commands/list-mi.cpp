/*
 * SPDX-FileCopyrightText: 2011 EfficiOS Inc.
 * SPDX-FileCopyrightText: 2020 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include "lttng/channel.h"
#include "lttng/domain.h"
#include "lttng/event.h"

#include <stdint.h>
#define _LGPL_SOURCE
#include "../command.hpp"
#include "list-mi.hpp"
#include "list-wrappers.hpp"

#include <common/mi-lttng.hpp>
#include <common/time.hpp>
#include <common/tracker.hpp>
#include <common/utils.hpp>

#include <lttng/domain-internal.hpp>
#include <lttng/lttng.h>
#include <lttng/stream-info.h>

#include <inttypes.h>
#include <popt.h>
#include <stdio.h>
#include <stdlib.h>

static struct mi_writer *the_writer;

/* Configuration for the list command */
static const list_cmd_config *the_config;

namespace {

int mi_write_event(const lttng_event& event, int is_open, lttng_domain_type domain_type)
{
	return mi_lttng_event(the_writer, const_cast<lttng_event *>(&event), is_open, domain_type);
}

int mi_write_domain(const lttng_domain& domain, int is_open)
{
	return mi_lttng_domain(the_writer, const_cast<lttng_domain *>(&domain), is_open);
}

} /* namespace */

template <typename InstrumentationPointSetType>
static int list_agent_ust_events(const InstrumentationPointSetType& instrumentation_points)
{
	int ret;
	pid_t cur_pid = 0;
	int pid_element_open = 0;
	lttng_domain domain;

	LTTNG_ASSERT(the_config->domain_type);
	std::memset(&domain, 0, sizeof(domain));
	domain.type = *the_config->domain_type;

	/* Open domains element */
	ret = mi_lttng_domains_open(the_writer);
	if (ret) {
		goto end;
	}

	/* Write domain */
	ret = mi_lttng_domain(the_writer, &domain, 1);
	if (ret) {
		goto end;
	}

	/* Open pids element element */
	ret = mi_lttng_pids_open(the_writer);
	if (ret) {
		goto end;
	}

	for (const auto& instrumentation_point : instrumentation_points) {
		if (cur_pid != instrumentation_point.pid()) {
			if (pid_element_open) {
				/* Close the previous events and pid element */
				ret = mi_lttng_close_multi_element(the_writer, 2);
				if (ret) {
					goto end;
				}
				pid_element_open = 0;
			}

			cur_pid = instrumentation_point.pid();
			const auto cmdline = instrumentation_point.cmdline();
			if (!cmdline) {
				ret = CMD_ERROR;
				goto end;
			}

			if (!pid_element_open) {
				/* Open and write a pid element */
				ret = mi_lttng_pid(the_writer, cur_pid, cmdline->c_str(), 1);
				if (ret) {
					goto end;
				}

				/* Open events element */
				ret = mi_lttng_events_open(the_writer);
				if (ret) {
					goto end;
				}

				pid_element_open = 1;
			}
		}

		/* Write an event */
		LTTNG_ASSERT(the_config->domain_type);
		ret = mi_write_event(instrumentation_point.lib(), 0, *the_config->domain_type);
		if (ret) {
			goto end;
		}
	}

	/* Close pids */
	ret = mi_lttng_writer_close_element(the_writer);
	if (ret) {
		goto end;
	}

	/* Close domain, domains */
	ret = mi_lttng_close_multi_element(the_writer, 2);
end:
	return ret;
}

static int list_ust_event_fields(const lttng::cli::ust_tracepoint_set& tracepoints)
{
	int ret;
	pid_t cur_pid = 0;
	int pid_element_open = 0;
	lttng_domain domain;

	std::memset(&domain, 0, sizeof(domain));
	domain.type = LTTNG_DOMAIN_UST;

	/* Open domains element */
	ret = mi_lttng_domains_open(the_writer);
	if (ret) {
		goto end;
	}

	/* Write domain */
	ret = mi_lttng_domain(the_writer, &domain, 1);
	if (ret) {
		goto end;
	}

	/* Open pids element */
	ret = mi_lttng_pids_open(the_writer);
	if (ret) {
		goto end;
	}

	for (const auto& tracepoint : tracepoints) {
		if (cur_pid != tracepoint.pid()) {
			if (pid_element_open) {
				/* Close the previous events, pid element */
				ret = mi_lttng_close_multi_element(the_writer, 2);
				if (ret) {
					goto end;
				}
				pid_element_open = 0;
			}

			cur_pid = tracepoint.pid();
			const auto cmdline = tracepoint.cmdline();
			if (!cmdline) {
				ret = CMD_ERROR;
				goto end;
			}

			if (!pid_element_open) {
				/* Open and write a pid element */
				ret = mi_lttng_pid(the_writer, cur_pid, cmdline->c_str(), 1);
				if (ret) {
					goto end;
				}

				/* Open events element */
				ret = mi_lttng_events_open(the_writer);
				if (ret) {
					goto end;
				}
				pid_element_open = 1;
			}
		}

		/* Open and write the event */
		ret = mi_write_event(tracepoint.lib(), 1, LTTNG_DOMAIN_UST);
		if (ret) {
			goto end;
		}

		/* Open a fields element */
		ret = mi_lttng_event_fields_open(the_writer);
		if (ret) {
			goto end;
		}

		/* Write all fields for this event */
		for (const auto& field : tracepoint.fields()) {
			ret = mi_lttng_event_field(the_writer,
						   const_cast<lttng_event_field *>(&field.lib()));
			if (ret) {
				goto end;
			}
		}

		/* Close fields and event elements */
		ret = mi_lttng_close_multi_element(the_writer, 2);
		if (ret) {
			goto end;
		}
	}

	/* Close pids, domain, domains */
	ret = mi_lttng_close_multi_element(the_writer, 3);
end:
	return ret;
}

static int list_kernel_events(const lttng::cli::kernel_tracepoint_set& tracepoints)
{
	int ret;
	lttng_domain domain;

	std::memset(&domain, 0, sizeof(domain));
	domain.type = LTTNG_DOMAIN_KERNEL;

	/* Open domains element */
	ret = mi_lttng_domains_open(the_writer);
	if (ret) {
		goto end;
	}

	/* Write domain */
	ret = mi_lttng_domain(the_writer, &domain, 1);
	if (ret) {
		goto end;
	}

	/* Open events */
	ret = mi_lttng_events_open(the_writer);
	if (ret) {
		goto end;
	}

	for (const auto& tracepoint : tracepoints) {
		ret = mi_write_event(tracepoint.lib(), 0, LTTNG_DOMAIN_KERNEL);
		if (ret) {
			goto end;
		}
	}

	/* close events, domain and domains */
	ret = mi_lttng_close_multi_element(the_writer, 3);
	if (ret) {
		goto end;
	}

end:
	return ret;
}

static int list_syscalls(const lttng::cli::kernel_syscall_set& syscalls)
{
	int ret;

	/* Open events */
	ret = mi_lttng_events_open(the_writer);
	if (ret) {
		goto end;
	}

	for (const auto& syscall : syscalls) {
		ret = mi_write_event(syscall.lib(), 0, LTTNG_DOMAIN_KERNEL);
		if (ret) {
			goto end;
		}
	}

	/* Close events. */
	ret = mi_lttng_writer_close_element(the_writer);
	if (ret) {
		goto end;
	}

end:
	return ret;
}

template <typename EventRuleSetType>
int list_events(const EventRuleSetType& event_rules, lttng_domain_type domain_type)
{
	int ret;

	/* Open events element */
	ret = mi_lttng_events_open(the_writer);
	if (ret) {
		goto end;
	}

	for (const auto& event : event_rules) {
		ret = mi_write_event(event.lib(), 0, domain_type);
		if (ret) {
			goto end;
		}
	}

	/* Close events element */
	ret = mi_lttng_writer_close_element(the_writer);

end:
	return ret;
}

static int write_channel_memory_usage(const lttng::cli::channel& channel)
{
	/* Memory usage information isn't available for a kernel channel */
	if (channel.domain_type() == LTTNG_DOMAIN_KERNEL) {
		return 0;
	}

	const auto data_stream_infos = channel.as_ust_or_java_python().data_stream_infos();

	return mi_lttng_data_stream_info_sets(the_writer,
					      &data_stream_infos.lib(),
					      static_cast<unsigned int>(data_stream_infos.size()));
}

static int list_channels(const lttng::cli::channel_set<lttng::cli::channel>& channels)
{
	int ret;
	unsigned int chan_found = 0;

	/* Open channels element */
	ret = mi_lttng_channels_open(the_writer);
	if (ret) {
		goto error;
	}

	for (const auto& channel : channels) {
		if (the_config->channel_name) {
			if (channel.name() != *the_config->channel_name) {
				continue;
			}
			chan_found = 1;
		}

		/* Write channel element  and leave it open */
		ret = mi_lttng_channel(the_writer, const_cast<lttng_channel *>(&channel.lib()), 1);
		if (ret) {
			goto error;
		}

		/* Listing events per channel */
		try {
			const auto event_rules = channel.event_rules();
			ret = list_events(event_rules, channel.domain_type());
			if (ret) {
				goto error;
			}
		} catch (const std::exception& e) {
			ERR_FMT("Failed to list event rules: {}", e.what());
			ret = CMD_ERROR;
			goto error;
		}

		/* Add memory usage, if available */
		ret = write_channel_memory_usage(channel);
		if (ret) {
			goto error;
		}

		/* Close channel element */
		ret = mi_lttng_writer_close_element(the_writer);
		if (ret) {
			goto error;
		}

		if (chan_found) {
			break;
		}
	}

	/* Close channels element */
	ret = mi_lttng_writer_close_element(the_writer);
	if (ret) {
		goto error;
	}

error:
	return ret;
}

static int output_empty_tracker(enum lttng_process_attr process_attr)
{
	int ret;

	ret = mi_lttng_process_attribute_tracker_open(the_writer, process_attr);
	if (ret) {
		goto end;
	}

	/* mi_lttng_process_attribute_tracker_open() opens two elements */
	ret = mi_lttng_close_multi_element(the_writer, 2);
end:
	return ret;
}

/*
 * Emit the values of a process-attribute tracker to the MI writer.
 */
static int write_process_attr_values(enum lttng_process_attr process_attr,
				     const std::set<lttng::cli::process_attr_value>& values)
{
	int ret = CMD_SUCCESS;

	for (const auto& value : values) {
		const auto value_type = value.type();

		if (value_type == LTTNG_PROCESS_ATTR_VALUE_TYPE_PID) {
			const auto pid = value.pid();
			if (pid) {
				ret = mi_lttng_integral_process_attribute_value(
					the_writer, process_attr, (int64_t) *pid, false);
			} else {
				ERR("Failed to get PID");
				ret = CMD_ERROR;
			}
		} else if (value_type == LTTNG_PROCESS_ATTR_VALUE_TYPE_UID) {
			const auto uid = value.uid();
			if (uid) {
				ret = mi_lttng_integral_process_attribute_value(
					the_writer, process_attr, (int64_t) *uid, false);
			} else {
				ERR("Failed to get UID");
				ret = CMD_ERROR;
			}
		} else if (value_type == LTTNG_PROCESS_ATTR_VALUE_TYPE_GID) {
			const auto gid = value.gid();
			if (gid) {
				ret = mi_lttng_integral_process_attribute_value(
					the_writer, process_attr, (int64_t) *gid, false);
			} else {
				ERR("Failed to get GID");
				ret = CMD_ERROR;
			}
		} else if (value_type == LTTNG_PROCESS_ATTR_VALUE_TYPE_USER_NAME) {
			const auto name = value.user_name();
			ret = mi_lttng_string_process_attribute_value(
				the_writer, process_attr, name.data(), false);
		} else if (value_type == LTTNG_PROCESS_ATTR_VALUE_TYPE_GROUP_NAME) {
			const auto name = value.group_name();
			ret = mi_lttng_string_process_attribute_value(
				the_writer, process_attr, name.data(), false);
		}

		if (ret) {
			goto end;
		}
	}

end:
	return ret;
}

static int list_sessions(const lttng::cli::session_list& sessions)
{
	int ret;

	/* Opening sessions element */
	ret = mi_lttng_sessions_open(the_writer);
	if (ret) {
		goto end;
	}

	/* Listing sessions */
	for (const auto& session : sessions) {
		ret = mi_lttng_session(the_writer, &session.lib(), 0);
		if (ret) {
			goto end;
		}
	}

	/* Closing sessions element */
	ret = mi_lttng_writer_close_element(the_writer);
	if (ret) {
		goto end;
	}

end:
	return ret;
}

namespace {

int write_tracker(enum lttng_process_attr process_attr,
		  const lttng::cli::process_attr_tracker& tracker)
{
	const auto policy = tracker.tracking_policy();

	if (policy == LTTNG_TRACKING_POLICY_EXCLUDE_ALL) {
		return output_empty_tracker(process_attr);
	}

	if (policy == LTTNG_TRACKING_POLICY_INCLUDE_ALL) {
		/* Skip - all is implicit */
		return CMD_SUCCESS;
	}

	/* INCLUDE_SET - output tracker */
	int ret = mi_lttng_process_attribute_tracker_open(the_writer, process_attr);
	if (ret) {
		return ret;
	}

	const auto inclusion_set = tracker.inclusion_set();
	if (inclusion_set) {
		ret = write_process_attr_values(process_attr, *inclusion_set);
		if (ret) {
			return ret;
		}
	}

	/* Close tracker element */
	return mi_lttng_close_multi_element(the_writer, 2);
}

} /* namespace */

/*
 * Write the trackers for a given domain to the MI writer.
 */
static int write_domain_trackers(const lttng::cli::domain& domain)
{
	int ret = CMD_SUCCESS;

	/* Trackers */
	ret = mi_lttng_trackers_open(the_writer);
	if (ret) {
		return ret;
	}

	/* Output trackers based on domain type */
	if (domain.type() == LTTNG_DOMAIN_KERNEL) {
		const auto kernel_domain = domain.as_kernel();
		ret = write_tracker(LTTNG_PROCESS_ATTR_PROCESS_ID,
				    kernel_domain.process_id_tracker());
		if (ret) {
			return ret;
		}
		ret = write_tracker(LTTNG_PROCESS_ATTR_VIRTUAL_PROCESS_ID,
				    kernel_domain.virtual_process_id_tracker());
		if (ret) {
			return ret;
		}
		ret = write_tracker(LTTNG_PROCESS_ATTR_USER_ID, kernel_domain.user_id_tracker());
		if (ret) {
			return ret;
		}
		ret = write_tracker(LTTNG_PROCESS_ATTR_VIRTUAL_USER_ID,
				    kernel_domain.virtual_user_id_tracker());
		if (ret) {
			return ret;
		}
		ret = write_tracker(LTTNG_PROCESS_ATTR_GROUP_ID, kernel_domain.group_id_tracker());
		if (ret) {
			return ret;
		}
		ret = write_tracker(LTTNG_PROCESS_ATTR_VIRTUAL_GROUP_ID,
				    kernel_domain.virtual_group_id_tracker());
		if (ret) {
			return ret;
		}
	} else if (domain.type() == LTTNG_DOMAIN_UST) {
		const auto ust_domain = domain.as_ust();
		ret = write_tracker(LTTNG_PROCESS_ATTR_VIRTUAL_PROCESS_ID,
				    ust_domain.virtual_process_id_tracker());
		if (ret) {
			return ret;
		}
		ret = write_tracker(LTTNG_PROCESS_ATTR_VIRTUAL_USER_ID,
				    ust_domain.virtual_user_id_tracker());
		if (ret) {
			return ret;
		}
		ret = write_tracker(LTTNG_PROCESS_ATTR_VIRTUAL_GROUP_ID,
				    ust_domain.virtual_group_id_tracker());
		if (ret) {
			return ret;
		}
	}

	/* Close trackers element */
	ret = mi_lttng_writer_close_element(the_writer);
	if (ret) {
		return ret;
	}

	return ret;
}

static int list_domains(const lttng::cli::domain_set& domains)
{
	int ret;
	/* Open domains element */
	ret = mi_lttng_domains_open(the_writer);
	if (ret) {
		goto end;
	}

	for (const auto& domain : domains) {
		ret = mi_write_domain(domain.lib(), 0);
		if (ret) {
			goto end;
		}
	}

	/* Closing domains element */
	ret = mi_lttng_writer_close_element(the_writer);
	if (ret) {
		goto end;
	}
end:
	return ret;
}

/*
 * Handle MI listing when no session name is provided.
 */
static int handle_no_session_name()
{
	int ret = CMD_SUCCESS;

	/* Listing sessions, kernel/ust events, or syscalls */
	if (!the_config->kernel && !the_config->userspace && !the_config->jul &&
	    !the_config->log4j && !the_config->log4j2 && !the_config->python) {
		/* List all sessions */
		const lttng::cli::session_list sessions;
		DBG("Session count %zu", sessions.size());
		ret = list_sessions(sessions);
		if (ret) {
			ret = CMD_ERROR;
			goto end;
		}
	}

	if (the_config->kernel) {
		if (the_config->syscall) {
			/* List syscalls */
			const lttng::cli::kernel_syscall_set syscalls;
			ret = list_syscalls(syscalls);
			if (ret) {
				ret = CMD_ERROR;
				goto end;
			}
		} else {
			/* List kernel events */
			const lttng::cli::kernel_tracepoint_set tracepoints;
			ret = list_kernel_events(tracepoints);
			if (ret) {
				ret = CMD_ERROR;
				goto end;
			}
		}
	}

	if (the_config->userspace) {
		const lttng::cli::ust_tracepoint_set tracepoints;
		if (the_config->fields) {
			/* List UST event fields */
			ret = list_ust_event_fields(tracepoints);
			if (ret) {
				ret = CMD_ERROR;
				goto end;
			}
		} else {
			/* List UST events */
			ret = list_agent_ust_events(tracepoints);
			if (ret) {
				ret = CMD_ERROR;
				goto end;
			}
		}
	}

	if (the_config->jul || the_config->log4j || the_config->log4j2 || the_config->python) {
		/* List agent events */
		LTTNG_ASSERT(the_config->domain_type);
		const lttng::cli::java_python_logger_set loggers(*the_config->domain_type);
		ret = list_agent_ust_events(loggers);
		if (ret) {
			ret = CMD_ERROR;
			goto end;
		}
	}

end:
	return ret;
}

/*
 * Write automatic rotation schedules for a given session to the MI writer.
 */
static int write_session_rotation_schedules(const lttng::cli::session& session)
{
	int ret = CMD_SUCCESS;

	const auto schedules = session.rotation_schedules();

	if (!schedules.is_empty()) {
		ret = mi_lttng_writer_open_element(the_writer, mi_lttng_element_rotation_schedules);
		if (ret) {
			ret = CMD_ERROR;
			goto end;
		}

		for (const auto& schedule : schedules) {
			ret = mi_lttng_rotation_schedule(the_writer, &schedule.lib());
			if (ret) {
				ret = CMD_ERROR;
				goto end;
			}
		}

		/* Close rotation_schedules element */
		ret = mi_lttng_writer_close_element(the_writer);
		if (ret) {
			ret = CMD_ERROR;
			goto end;
		}
	}

end:
	return ret;
}

/*
 * List all domains of a session, including trackers and channels, and emit
 * them to the MI writer. This function opens and closes the `domains` MI
 * element internally and leaves the surrounding `session`/`sessions` elements
 * to the caller.
 */
static int list_all_session_domains(const lttng::cli::session& session)
{
	int ret = CMD_SUCCESS;

	const auto session_domains = session.domains();

	ret = mi_lttng_domains_open(the_writer);
	if (ret) {
		ret = CMD_ERROR;
		goto end;
	}

	for (const auto& domain : session_domains) {
		ret = mi_write_domain(domain.lib(), 1);
		if (ret) {
			ret = CMD_ERROR;
			goto close_domains_element;
		}

		if (domain.type() == LTTNG_DOMAIN_JUL || domain.type() == LTTNG_DOMAIN_LOG4J ||
		    domain.type() == LTTNG_DOMAIN_LOG4J2 || domain.type() == LTTNG_DOMAIN_PYTHON) {
			/* List agent event rules directly (no channels for Java/Python domains) */
			ret = list_events(domain.as_java_python().event_rules(), domain.type());
			if (ret) {
				goto close_domain_element;
			}

			/* Close domain element and continue */
			ret = mi_lttng_writer_close_element(the_writer);
			if (ret) {
				ret = CMD_ERROR;
				goto close_domains_element;
			}
			continue;
		}

		/* Trackers for kernel and UST */
		if (domain.type() == LTTNG_DOMAIN_KERNEL || domain.type() == LTTNG_DOMAIN_UST) {
			ret = write_domain_trackers(domain);
			if (ret) {
				goto close_domain_element;
			}
		}

		/* List channels */
		try {
			const auto channels = domain.channels();
			ret = list_channels(channels);
			if (ret) {
				goto close_domain_element;
			}
		} catch (const std::exception& e) {
			ERR_FMT("Failed to list channels: {}", e.what());
			ret = CMD_ERROR;
			goto close_domain_element;
		}

		/* Close domain element */
		ret = mi_lttng_writer_close_element(the_writer);
		if (ret) {
			ret = CMD_ERROR;
			goto close_domains_element;
		}
		continue;

	close_domain_element:
	{
		int close_ret = mi_lttng_writer_close_element(the_writer);
		(void) close_ret;
	}
		goto close_domains_element;
	}

close_domains_element:
{
	int close_ret = mi_lttng_writer_close_element(the_writer);
	(void) close_ret;
}
end:
	return ret;
}

/*
 * Handle MI listing when a session name is provided.
 */
static int handle_with_session_name()
{
	/* List session attributes */
	const lttng::cli::session_list sessions;

	DBG("Session count %zu", sessions.size());

	/* Open sessions element */
	int ret = mi_lttng_sessions_open(the_writer);
	if (ret) {
		return ret;
	}

	/* Find the session */
	LTTNG_ASSERT(the_config->session_name);
	const auto found_session = sessions.find_by_name(the_config->session_name->c_str());

	if (!found_session) {
		ERR("Session '%s' not found", the_config->session_name->c_str());
		return -LTTNG_ERR_SESS_NOT_FOUND;
	}

	ret = mi_lttng_session(the_writer, &found_session->lib(), 1);
	if (ret) {
		return ret;
	}

	/* Automatic rotation schedules */
	ret = write_session_rotation_schedules(*found_session);
	if (ret) {
		return ret;
	}

	/* Domain listing */
	if (the_config->domain) {
		const auto session_domains = found_session->domains();
		return list_domains(session_domains);
	}

	/* Channel listing */
	if (the_config->kernel || the_config->userspace) {
		/* Find the requested domain from the session's domains */
		const auto session_domains = found_session->domains();

		LTTNG_ASSERT(the_config->domain_type);

		const auto found_domain = session_domains.find_by_type(*the_config->domain_type);

		if (!found_domain) {
			ERR("Domain not found in session");
			return CMD_ERROR;
		}

		/* Add domains and domain element */
		ret = mi_lttng_domains_open(the_writer);
		if (ret) {
			return ret;
		}

		/* Open domain and leave it open for nested elements */
		ret = mi_write_domain(found_domain->lib(), 1);
		if (ret) {
			return ret;
		}

		/* Trackers */
		ret = write_domain_trackers(*found_domain);
		if (ret) {
			return ret;
		}

		/* Channels */
		try {
			const auto channels = found_domain->channels();
			ret = list_channels(channels);
			if (ret) {
				return ret;
			}
		} catch (const std::exception& e) {
			ERR_FMT("Failed to list channels: {}", e.what());
			return CMD_ERROR;
		}

		/* Close domain element */
		ret = mi_lttng_writer_close_element(the_writer);
		if (ret) {
			return CMD_ERROR;
		}

		/* Close the domains, session and sessions element */
		ret = mi_lttng_close_multi_element(the_writer, 3);
		if (ret) {
			return CMD_ERROR;
		}

		return CMD_SUCCESS;
	}

	/* List all domains */
	ret = list_all_session_domains(*found_session);
	if (ret) {
		return ret;
	}

	/* Close the session and sessions element */
	ret = mi_lttng_close_multi_element(the_writer, 2);
	if (ret) {
		return CMD_ERROR;
	}

	return CMD_SUCCESS;
}

/*
 * Entry point for machine interface list command.
 */
int list_mi(const list_cmd_config& config)
{
	int ret = CMD_SUCCESS;

	/* Cache configuration for use by helpers */
	the_config = &config;

	/* Initialize writer */
	the_writer = mi_lttng_writer_create(fileno(stdout), lttng_opt_mi);
	if (!the_writer) {
		ret = CMD_ERROR;
		goto end;
	}

	/* Open command element */
	ret = mi_lttng_writer_command_open(the_writer, mi_lttng_element_command_list);
	if (ret) {
		ret = CMD_ERROR;
		goto end;
	}

	/* Open output element */
	ret = mi_lttng_writer_open_element(the_writer, mi_lttng_element_command_output);
	if (ret) {
		ret = CMD_ERROR;
		goto end;
	}

	if (!the_config->session_name) {
		ret = handle_no_session_name();
	} else {
		ret = handle_with_session_name();
	}

	if (ret) {
		goto end;
	}

	/* Close output element */
	{
		int close_ret = mi_lttng_writer_close_element(the_writer);
		if (close_ret) {
			ret = ret ? ret : CMD_ERROR;
		}
	}

	/* Command element close */
	{
		int close_ret = mi_lttng_writer_command_close(the_writer);
		if (close_ret) {
			ret = ret ? ret : CMD_ERROR;
		}
	}

end:
	/* Mi clean-up */
	if (the_writer && mi_lttng_writer_destroy(the_writer)) {
		/* Preserve original error code */
		ret = ret ? ret : -LTTNG_ERR_MI_IO_FAIL;
	}

	return ret;
}
