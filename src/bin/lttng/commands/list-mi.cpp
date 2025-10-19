/*
 * SPDX-FileCopyrightText: 2011 EfficiOS Inc.
 * SPDX-FileCopyrightText: 2020 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include "common/exception.hpp"
#include "common/macros.hpp"
#include "lttng/channel.h"
#include "lttng/domain.h"
#include "lttng/event.h"

#include <cstdint>
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

namespace {

/* The XML writer */
struct mi_writer *the_writer;

/* Configuration for the list command */
const list_cmd_config *the_config;

int mi_write_event(const lttng_event& event, bool is_open, lttng_domain_type domain_type)
{
	return mi_lttng_event(the_writer, const_cast<lttng_event *>(&event), is_open, domain_type);
}

int mi_write_domain(const lttng_domain& domain, bool is_open)
{
	return mi_lttng_domain(the_writer, const_cast<lttng_domain *>(&domain), is_open);
}

int mi_lttng_pseudo_domain(lttng_domain_type type, bool is_open)
{
	lttng_domain domain;

	std::memset(&domain, 0, sizeof(domain));
	domain.type = type;
	return mi_lttng_domain(the_writer, &domain, is_open);
}

template <typename InstrumentationPointSetType>
void list_agent_ust_events(const InstrumentationPointSetType& instrumentation_points)
{
	LTTNG_ASSERT(the_config->domain_type);

	/* Open domains element */
	if (mi_lttng_domains_open(the_writer)) {
		LTTNG_THROW_ERROR("Failed to open XML domains element");
	}

	/* Write domain */
	if (mi_lttng_pseudo_domain(*the_config->domain_type, true)) {
		LTTNG_THROW_ERROR("Failed to write XML domain");
	}

	/* Open pids element element */
	if (mi_lttng_pids_open(the_writer)) {
		LTTNG_THROW_ERROR("Failed to open XML PIDs element");
	}

	pid_t cur_pid = 0;
	auto pid_element_open = false;

	for (const auto& instrumentation_point : instrumentation_points) {
		if (cur_pid != instrumentation_point.pid()) {
			if (pid_element_open) {
				/* Close the previous events and PID element */
				if (mi_lttng_close_multi_element(the_writer, 2)) {
					LTTNG_THROW_ERROR("Failed to close XML elements");
				}

				pid_element_open = false;
			}

			cur_pid = instrumentation_point.pid();

			const auto cmdline = instrumentation_point.cmdline();

			if (!cmdline) {
				LTTNG_THROW_ERROR("Failed to get command line of PID");
			}

			if (!pid_element_open) {
				/* Open and write a pid element */
				if (mi_lttng_pid(the_writer, cur_pid, cmdline->c_str(), true)) {
					LTTNG_THROW_ERROR("Failed to write XML PID element");
				}

				/* Open events element */
				if (mi_lttng_events_open(the_writer)) {
					LTTNG_THROW_ERROR("Failed to open XML events element");
				}

				pid_element_open = true;
			}
		}

		/* Write an event */
		LTTNG_ASSERT(the_config->domain_type);

		if (mi_write_event(instrumentation_point.lib(), false, *the_config->domain_type)) {
			LTTNG_THROW_ERROR("Failed to write XML event");
		}
	}

	/* Close pids */
	if (mi_lttng_writer_close_element(the_writer)) {
		LTTNG_THROW_ERROR("Failed to close XML PIDs element");
	}

	/* Close domain, domains */
	if (mi_lttng_close_multi_element(the_writer, 2)) {
		LTTNG_THROW_ERROR("Failed to close XML domain and domains elements");
	}
}

void list_ust_event_fields(const lttng::cli::ust_tracepoint_set& tracepoints)
{
	/* Open domains element */
	if (mi_lttng_domains_open(the_writer)) {
		LTTNG_THROW_ERROR("Failed to open XML domains element");
	}

	/* Write domain */
	if (mi_lttng_pseudo_domain(LTTNG_DOMAIN_UST, true)) {
		LTTNG_THROW_ERROR("Failed to write XML domain");
	}

	/* Open pids element */
	if (mi_lttng_pids_open(the_writer)) {
		LTTNG_THROW_ERROR("Failed to open XML PIDs element");
	}

	pid_t cur_pid = 0;
	auto pid_element_open = false;

	for (const auto& tracepoint : tracepoints) {
		if (cur_pid != tracepoint.pid()) {
			if (pid_element_open) {
				/* Close the previous events, pid element */
				if (mi_lttng_close_multi_element(the_writer, 2)) {
					LTTNG_THROW_ERROR("Failed to close XML elements");
				}

				pid_element_open = false;
			}

			cur_pid = tracepoint.pid();

			const auto cmdline = tracepoint.cmdline();

			if (!cmdline) {
				LTTNG_THROW_ERROR("Failed to get command line of PID");
			}

			if (!pid_element_open) {
				/* Open and write a pid element */
				if (mi_lttng_pid(the_writer, cur_pid, cmdline->c_str(), true)) {
					LTTNG_THROW_ERROR("Failed to write XML PID element");
				}

				/* Open events element */
				if (mi_lttng_events_open(the_writer)) {
					LTTNG_THROW_ERROR("Failed to open XML events element");
				}

				pid_element_open = true;
			}
		}

		/* Open and write the event */
		if (mi_write_event(tracepoint.lib(), true, LTTNG_DOMAIN_UST)) {
			LTTNG_THROW_ERROR("Failed to write XML event");
		}

		/* Open a fields element */
		if (mi_lttng_event_fields_open(the_writer)) {
			LTTNG_THROW_ERROR("Failed to open XML event fields element");
		}

		/* Write all fields for this event */
		for (const auto& field : tracepoint.fields()) {
			if (mi_lttng_event_field(the_writer,
						 const_cast<lttng_event_field *>(&field.lib()))) {
				LTTNG_THROW_ERROR("Failed to write XML event field");
			}
		}

		/* Close fields and event elements */
		if (mi_lttng_close_multi_element(the_writer, 2)) {
			LTTNG_THROW_ERROR("Failed to close XML fields and event elements");
		}
	}

	/* Close pids, domain, domains */
	if (mi_lttng_close_multi_element(the_writer, 3)) {
		LTTNG_THROW_ERROR("Failed to close XML PIDs, domain, and domains elements");
	}
}

void list_kernel_events()
{
	/* Open domains element */
	if (mi_lttng_domains_open(the_writer)) {
		LTTNG_THROW_ERROR("Failed to open XML domains element");
	}

	/* Write domain */
	if (mi_lttng_pseudo_domain(LTTNG_DOMAIN_KERNEL, true)) {
		LTTNG_THROW_ERROR("Failed to write XML domain");
	}

	/* Open events */
	if (mi_lttng_events_open(the_writer)) {
		LTTNG_THROW_ERROR("Failed to open XML events element");
	}

	for (const auto& tracepoint : lttng::cli::kernel_tracepoint_set()) {
		if (mi_write_event(tracepoint.lib(), false, LTTNG_DOMAIN_KERNEL)) {
			LTTNG_THROW_ERROR("Failed to write XML event");
		}
	}

	/* close events, domain and domains */
	if (mi_lttng_close_multi_element(the_writer, 3)) {
		LTTNG_THROW_ERROR("Failed to close XML events, domain, and domains elements");
	}
}

void list_syscalls()
{
	/* Open events */
	if (mi_lttng_events_open(the_writer)) {
		LTTNG_THROW_ERROR("Failed to open XML events element");
	}

	for (const auto& syscall : lttng::cli::kernel_syscall_set()) {
		if (mi_write_event(syscall.lib(), false, LTTNG_DOMAIN_KERNEL)) {
			LTTNG_THROW_ERROR("Failed to write XML event");
		}
	}

	/* Close events */
	if (mi_lttng_writer_close_element(the_writer)) {
		LTTNG_THROW_ERROR("Failed to close XML events element");
	}
}

template <typename EventRuleSetType>
void list_events(const EventRuleSetType& event_rules, const lttng_domain_type domain_type)
{
	/* Open events element */
	if (mi_lttng_events_open(the_writer)) {
		LTTNG_THROW_ERROR("Failed to open XML events element");
	}

	for (const auto& event_rule : event_rules) {
		if (mi_write_event(event_rule.lib(), false, domain_type)) {
			LTTNG_THROW_ERROR("Failed to write XML event");
		}
	}

	/* Close events element */
	if (mi_lttng_writer_close_element(the_writer)) {
		LTTNG_THROW_ERROR("Failed to close XML events element");
	}
}

void write_channel_memory_usage(const lttng::cli::channel& channel)
{
	/* Memory usage information isn't available for a kernel channel */
	if (channel.domain_type() == LTTNG_DOMAIN_KERNEL) {
		return;
	}

	const auto data_stream_infos = channel.as_ust_or_java_python().data_stream_infos();

	if (mi_lttng_data_stream_info_sets(the_writer,
					   &data_stream_infos.lib(),
					   static_cast<unsigned int>(data_stream_infos.size()))) {
		LTTNG_THROW_ERROR("Failed to write XML data stream info sets");
	}
}

void list_channels(const lttng::cli::channel_set<lttng::cli::channel>& channels)
{
	/* Open channels element */
	if (mi_lttng_channels_open(the_writer)) {
		LTTNG_THROW_ERROR("Failed to open XML channels element");
	}

	for (const auto& channel : channels) {
		/* Filter by name if needed */
		auto chan_found = false;

		if (the_config->channel_name) {
			if (channel.name() != *the_config->channel_name) {
				continue;
			}

			chan_found = true;
		}

		/* Write channel element  and leave it open */
		if (mi_lttng_channel(
			    the_writer, const_cast<lttng_channel *>(&channel.lib()), true)) {
			LTTNG_THROW_ERROR("Failed to write XML channel element");
		}

		/* Listing events per channel */
		list_events(channel.event_rules(), channel.domain_type());

		/* Add memory usage, if available */
		write_channel_memory_usage(channel);

		/* Close channel element */
		if (mi_lttng_writer_close_element(the_writer)) {
			LTTNG_THROW_ERROR("Failed to close XML channel element");
		}

		if (chan_found) {
			break;
		}
	}

	/* Close channels element */
	if (mi_lttng_writer_close_element(the_writer)) {
		LTTNG_THROW_ERROR("Failed to close XML channels element");
	}
}

void output_empty_tracker(const lttng_process_attr process_attr)
{
	if (mi_lttng_process_attribute_tracker_open(the_writer, process_attr)) {
		LTTNG_THROW_ERROR("Failed to open XML process attribute tracker element");
	}

	/* mi_lttng_process_attribute_tracker_open() opens two elements */
	if (mi_lttng_close_multi_element(the_writer, 2)) {
		LTTNG_THROW_ERROR("Failed to close XML process attribute tracker elements");
	}
}

void write_process_attr_values(const lttng_process_attr process_attr,
			       const std::set<lttng::cli::process_attr_value>& values)
{
	for (const auto& value : values) {
		if (value.type() == LTTNG_PROCESS_ATTR_VALUE_TYPE_PID) {
			if (const auto pid = value.pid()) {
				if (mi_lttng_integral_process_attribute_value(
					    the_writer,
					    process_attr,
					    static_cast<int64_t>(*pid),
					    false)) {
					LTTNG_THROW_ERROR("Failed to write XML PID value");
				}
			} else {
				LTTNG_THROW_ERROR("Failed to get expected PID");
			}
		} else if (value.type() == LTTNG_PROCESS_ATTR_VALUE_TYPE_UID) {
			if (const auto uid = value.uid()) {
				if (mi_lttng_integral_process_attribute_value(
					    the_writer,
					    process_attr,
					    static_cast<int64_t>(*uid),
					    false)) {
					LTTNG_THROW_ERROR("Failed to write XML UID value");
				}
			} else {
				LTTNG_THROW_ERROR("Failed to get expected UID");
			}
		} else if (value.type() == LTTNG_PROCESS_ATTR_VALUE_TYPE_GID) {
			if (const auto gid = value.gid()) {
				if (mi_lttng_integral_process_attribute_value(
					    the_writer,
					    process_attr,
					    static_cast<int64_t>(*gid),
					    false)) {
					LTTNG_THROW_ERROR("Failed to write XML GID value");
				}
			} else {
				LTTNG_THROW_ERROR("Failed to get expected GID");
			}
		} else if (value.type() == LTTNG_PROCESS_ATTR_VALUE_TYPE_USER_NAME) {
			if (const auto name = value.user_name()) {
				if (mi_lttng_string_process_attribute_value(
					    the_writer, process_attr, name.data(), false)) {
					LTTNG_THROW_ERROR("Failed to write XML user name value");
				}
			} else {
				LTTNG_THROW_ERROR("Failed to get expected user name");
			}
		} else if (value.type() == LTTNG_PROCESS_ATTR_VALUE_TYPE_GROUP_NAME) {
			if (const auto name = value.group_name()) {
				if (mi_lttng_string_process_attribute_value(
					    the_writer, process_attr, name.data(), false)) {
					LTTNG_THROW_ERROR("Failed to write XML group name value");
				}
			} else {
				LTTNG_THROW_ERROR("Failed to get expected group name");
			}
		}
	}
}

void list_sessions(const lttng::cli::session_list& sessions)
{
	/* Opening sessions element */
	if (mi_lttng_sessions_open(the_writer)) {
		LTTNG_THROW_ERROR("Failed to open XML sessions element");
	}

	/* Listing sessions */
	for (const auto& session : sessions) {
		if (mi_lttng_session(the_writer, &session.lib(), false)) {
			LTTNG_THROW_ERROR("Failed to write XML session");
		}
	}

	/* Closing sessions element */
	if (mi_lttng_writer_close_element(the_writer)) {
		LTTNG_THROW_ERROR("Failed to close XML sessions element");
	}
}

void write_tracker(const lttng_process_attr process_attr,
		   const lttng::cli::process_attr_tracker& tracker)
{
	const auto policy = tracker.tracking_policy();

	if (policy == LTTNG_TRACKING_POLICY_EXCLUDE_ALL) {
		output_empty_tracker(process_attr);
		return;
	} else if (policy == LTTNG_TRACKING_POLICY_INCLUDE_ALL) {
		/* Skip: "all" is implicit */
		return;
	}

	/* `LTTNG_TRACKING_POLICY_INCLUDE_SET`: output tracker */
	if (mi_lttng_process_attribute_tracker_open(the_writer, process_attr)) {
		LTTNG_THROW_ERROR("Failed to open XML process attribute tracker element");
	}

	if (const auto inclusion_set = tracker.inclusion_set()) {
		write_process_attr_values(process_attr, *inclusion_set);
	}

	/* Close tracker element */
	if (mi_lttng_close_multi_element(the_writer, 2)) {
		LTTNG_THROW_ERROR("Failed to close XML tracker elements");
	}
}

void write_domain_trackers(const lttng::cli::domain& domain)
{
	/* Trackers */
	if (mi_lttng_trackers_open(the_writer)) {
		LTTNG_THROW_ERROR("Failed to open XML trackers element");
	}

	/* Output trackers based on domain type */
	if (domain.type() == LTTNG_DOMAIN_KERNEL) {
		const auto kernel_domain = domain.as_kernel();

		write_tracker(LTTNG_PROCESS_ATTR_PROCESS_ID, kernel_domain.process_id_tracker());
		write_tracker(LTTNG_PROCESS_ATTR_VIRTUAL_PROCESS_ID,
			      kernel_domain.virtual_process_id_tracker());
		write_tracker(LTTNG_PROCESS_ATTR_USER_ID, kernel_domain.user_id_tracker());
		write_tracker(LTTNG_PROCESS_ATTR_VIRTUAL_USER_ID,
			      kernel_domain.virtual_user_id_tracker());
		write_tracker(LTTNG_PROCESS_ATTR_GROUP_ID, kernel_domain.group_id_tracker());
		write_tracker(LTTNG_PROCESS_ATTR_VIRTUAL_GROUP_ID,
			      kernel_domain.virtual_group_id_tracker());
	} else if (domain.type() == LTTNG_DOMAIN_UST) {
		const auto ust_domain = domain.as_ust();

		write_tracker(LTTNG_PROCESS_ATTR_VIRTUAL_PROCESS_ID,
			      ust_domain.virtual_process_id_tracker());
		write_tracker(LTTNG_PROCESS_ATTR_VIRTUAL_USER_ID,
			      ust_domain.virtual_user_id_tracker());
		write_tracker(LTTNG_PROCESS_ATTR_VIRTUAL_GROUP_ID,
			      ust_domain.virtual_group_id_tracker());
	}

	/* Close trackers element */
	if (mi_lttng_writer_close_element(the_writer)) {
		LTTNG_THROW_ERROR("Failed to close XML trackers element");
	}
}

void list_domains(const lttng::cli::domain_set& domains)
{
	/* Open domains element */
	if (mi_lttng_domains_open(the_writer)) {
		LTTNG_THROW_ERROR("Failed to open XML domains element");
	}

	for (const auto& domain : domains) {
		if (mi_write_domain(domain.lib(), false)) {
			LTTNG_THROW_ERROR("Failed to write XML domain");
		}
	}

	/* Closing domains element */
	if (mi_lttng_writer_close_element(the_writer)) {
		LTTNG_THROW_ERROR("Failed to close XML domains element");
	}
}

/*
 * Handle MI listing when no session name is provided.
 */
void handle_no_session_name()
{
	/* Listing sessions or instrumentation points */
	if (!the_config->kernel && !the_config->userspace && !the_config->jul &&
	    !the_config->log4j && !the_config->log4j2 && !the_config->python) {
		/* List all sessions */
		const lttng::cli::session_list sessions;

		DBG("Session count %zu", sessions.size());
		list_sessions(sessions);
	}

	if (the_config->kernel) {
		if (the_config->syscall) {
			/* List kernel system calls */
			list_syscalls();
		} else {
			/* List kernel tracepoints */
			list_kernel_events();
		}
	}

	if (the_config->userspace) {
		const lttng::cli::ust_tracepoint_set tracepoints;

		if (the_config->fields) {
			/* List UST tracepoint fields */
			list_ust_event_fields(tracepoints);
		} else {
			/* List UST tracepoints */
			list_agent_ust_events(tracepoints);
		}
	}

	if (the_config->jul || the_config->log4j || the_config->log4j2 || the_config->python) {
		/* List agent loggers */
		LTTNG_ASSERT(the_config->domain_type);

		const lttng::cli::java_python_logger_set loggers(*the_config->domain_type);

		list_agent_ust_events(loggers);
	}
}

void write_session_rotation_schedules(const lttng::cli::session& session)
{
	const auto schedules = session.rotation_schedules();

	if (!schedules.is_empty()) {
		if (mi_lttng_writer_open_element(the_writer, mi_lttng_element_rotation_schedules)) {
			LTTNG_THROW_ERROR("Failed to open XML rotation schedules element");
		}

		for (const auto& schedule : schedules) {
			if (mi_lttng_rotation_schedule(the_writer, &schedule.lib())) {
				LTTNG_THROW_ERROR("Failed to write XML rotation schedule");
			}
		}

		/* Close rotation_schedules element */
		if (mi_lttng_writer_close_element(the_writer)) {
			LTTNG_THROW_ERROR("Failed to close XML rotation schedules element");
		}
	}
}

void list_all_session_domains(const lttng::cli::session& session)
{
	if (mi_lttng_domains_open(the_writer)) {
		LTTNG_THROW_ERROR("Failed to open XML domains element");
	}

	for (const auto& domain : session.domains()) {
		if (mi_write_domain(domain.lib(), true)) {
			LTTNG_THROW_ERROR("Failed to write XML domain");
		}

		if (domain.type() == LTTNG_DOMAIN_JUL || domain.type() == LTTNG_DOMAIN_LOG4J ||
		    domain.type() == LTTNG_DOMAIN_LOG4J2 || domain.type() == LTTNG_DOMAIN_PYTHON) {
			/* List agent event rules directly (no channels for Java/Python domains) */
			list_events(domain.as_java_python().event_rules(), domain.type());

			/* Close domain element and continue */
			if (mi_lttng_writer_close_element(the_writer)) {
				LTTNG_THROW_ERROR("Failed to close XML domain element");
			}

			continue;
		}

		/* Trackers for kernel and UST */
		if (domain.type() == LTTNG_DOMAIN_KERNEL || domain.type() == LTTNG_DOMAIN_UST) {
			write_domain_trackers(domain);
		}

		/* List channels */
		list_channels(domain.channels());

		/* Close domain element */
		if (mi_lttng_writer_close_element(the_writer)) {
			LTTNG_THROW_ERROR("Failed to close XML domain element");
		}
	}

	/* Close domains element */
	if (mi_lttng_writer_close_element(the_writer)) {
		LTTNG_THROW_ERROR("Failed to close XML domains element");
	}
}

/*
 * Handle MI listing when a session name is provided.
 */
void handle_with_session_name()
{
	LTTNG_ASSERT(the_config->session_name);

	/* List session attributes */
	const lttng::cli::session_list sessions;

	DBG("Session count %zu", sessions.size());

	/* Open sessions element */
	if (mi_lttng_sessions_open(the_writer)) {
		LTTNG_THROW_ERROR("Failed to open XML sessions element");
	}

	/* Find the session */
	LTTNG_ASSERT(the_config->session_name);

	const auto found_session = sessions.find_by_name(the_config->session_name->c_str());

	if (!found_session) {
		LTTNG_THROW_ERROR(
			lttng::format("Session '{}' not found", the_config->session_name->c_str()));
	}

	if (mi_lttng_session(the_writer, &found_session->lib(), true)) {
		LTTNG_THROW_ERROR("Failed to write XML session");
	}

	/* Automatic rotation schedules */
	write_session_rotation_schedules(*found_session);

	/* Domain listing */
	if (the_config->domain) {
		list_domains(found_session->domains());
		return;
	}

	/* Channel listing */
	if (the_config->kernel || the_config->userspace) {
		/* Find the requested domain from the session's domains */
		LTTNG_ASSERT(the_config->domain_type);

		const auto found_domain =
			found_session->domains().find_by_type(*the_config->domain_type);

		if (!found_domain) {
			LTTNG_THROW_ERROR("Domain not found in session");
		}

		/* Add domains and domain element */
		if (mi_lttng_domains_open(the_writer)) {
			LTTNG_THROW_ERROR("Failed to open XML domains element");
		}

		/* Open domain and leave it open for nested elements */
		if (mi_write_domain(found_domain->lib(), true)) {
			LTTNG_THROW_ERROR("Failed to write XML domain");
		}

		/* Trackers */
		write_domain_trackers(*found_domain);

		/* Channels */
		list_channels(found_domain->channels());

		/* Close domain element */
		if (mi_lttng_writer_close_element(the_writer)) {
			LTTNG_THROW_ERROR("Failed to close XML domain element");
		}

		/* Close the domains, session and sessions element */
		if (mi_lttng_close_multi_element(the_writer, 3)) {
			LTTNG_THROW_ERROR(
				"Failed to close XML domains, session, and sessions elements");
		}

		return;
	}

	/* List all domains */
	list_all_session_domains(*found_session);

	/* Close the session and sessions element */
	if (mi_lttng_close_multi_element(the_writer, 2)) {
		LTTNG_THROW_ERROR("Failed to close XML session and sessions elements");
	}
}

} /* namespace */

/*
 * Entry point for machine interface list command.
 */
int list_mi(const list_cmd_config& config)
{
	/* Cache configuration for use by helpers */
	the_config = &config;

	/* Initialize writer */
	const mi_writer_uptr writer(mi_lttng_writer_create(fileno(stdout), lttng_opt_mi));

	LTTNG_ASSERT(writer);
	the_writer = writer.get();

	/* Open command element */
	if (mi_lttng_writer_command_open(the_writer, mi_lttng_element_command_list)) {
		LTTNG_THROW_ERROR("Failed to open XML command element");
	}

	/* Open output element */
	if (mi_lttng_writer_open_element(the_writer, mi_lttng_element_command_output)) {
		LTTNG_THROW_ERROR("Failed to open XML output element");
	}

	if (!the_config->session_name) {
		handle_no_session_name();
	} else {
		handle_with_session_name();
	}

	/* Close output element */
	if (mi_lttng_writer_close_element(the_writer)) {
		LTTNG_THROW_ERROR("Failed to close XML output element");
	}

	/* Command element close */
	if (mi_lttng_writer_command_close(the_writer)) {
		LTTNG_THROW_ERROR("Failed to open XML writer element");
	}

	return CMD_SUCCESS;
}
