/*
 * SPDX-FileCopyrightText: 2011 EfficiOS Inc.
 * SPDX-FileCopyrightText: 2020 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include <stdint.h>
#define _LGPL_SOURCE
#include "../command.hpp"
#include "list-common.hpp"
#include "list-memory-usage.hpp"
#include "list-mi.hpp"

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
#include <string.h>

namespace lcm = lttng::cli::memory_usage;

static struct mi_writer *the_writer;
static struct lttng_handle *the_handle;

/* Cached command-line options for MI handling in this TU. */
static int opt_kernel;
static int opt_userspace;
static int opt_jul;
static int opt_log4j;
static int opt_log4j2;
static int opt_python;
static int opt_fields;
static int opt_syscall;
static int opt_domain;
static const char *opt_channel;

static int list_agent_ust_events(struct lttng_event *events, int count, struct lttng_domain *domain)
{
	int ret, i;
	pid_t cur_pid = 0;
	char *cmdline = nullptr;
	int pid_element_open = 0;

	/* Open domains element */
	ret = mi_lttng_domains_open(the_writer);
	if (ret) {
		goto end;
	}

	/* Write domain */
	ret = mi_lttng_domain(the_writer, domain, 1);
	if (ret) {
		goto end;
	}

	/* Open pids element element */
	ret = mi_lttng_pids_open(the_writer);
	if (ret) {
		goto end;
	}

	for (i = 0; i < count; i++) {
		if (cur_pid != events[i].pid) {
			if (pid_element_open) {
				/* Close the previous events and pid element */
				ret = mi_lttng_close_multi_element(the_writer, 2);
				if (ret) {
					goto end;
				}
				pid_element_open = 0;
			}

			cur_pid = events[i].pid;
			cmdline = get_cmdline_by_pid(cur_pid);
			if (!cmdline) {
				ret = CMD_ERROR;
				goto end;
			}

			if (!pid_element_open) {
				/* Open and write a pid element */
				ret = mi_lttng_pid(the_writer, cur_pid, cmdline, 1);
				if (ret) {
					goto error;
				}

				/* Open events element */
				ret = mi_lttng_events_open(the_writer);
				if (ret) {
					goto error;
				}

				pid_element_open = 1;
			}
			free(cmdline);
		}

		/* Write an event */
		ret = mi_lttng_event(the_writer, &events[i], 0, the_handle->domain.type);
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
error:
	free(cmdline);
	return ret;
}

static int
list_ust_event_fields(struct lttng_event_field *fields, int count, struct lttng_domain *domain)
{
	int ret, i;
	pid_t cur_pid = 0;
	char *cmdline = nullptr;
	int pid_element_open = 0;
	int event_element_open = 0;
	struct lttng_event cur_event;

	memset(&cur_event, 0, sizeof(cur_event));

	/* Open domains element */
	ret = mi_lttng_domains_open(the_writer);
	if (ret) {
		goto end;
	}

	/* Write domain */
	ret = mi_lttng_domain(the_writer, domain, 1);
	if (ret) {
		goto end;
	}

	/* Open pids element */
	ret = mi_lttng_pids_open(the_writer);
	if (ret) {
		goto end;
	}

	for (i = 0; i < count; i++) {
		if (cur_pid != fields[i].event.pid) {
			if (pid_element_open) {
				if (event_element_open) {
					/* Close the previous field element and event. */
					ret = mi_lttng_close_multi_element(the_writer, 2);
					if (ret) {
						goto end;
					}
					event_element_open = 0;
				}
				/* Close the previous events, pid element */
				ret = mi_lttng_close_multi_element(the_writer, 2);
				if (ret) {
					goto end;
				}
				pid_element_open = 0;
			}

			cur_pid = fields[i].event.pid;
			cmdline = get_cmdline_by_pid(cur_pid);
			if (!pid_element_open) {
				/* Open and write a pid element */
				ret = mi_lttng_pid(the_writer, cur_pid, cmdline, 1);
				if (ret) {
					goto error;
				}

				/* Open events element */
				ret = mi_lttng_events_open(the_writer);
				if (ret) {
					goto error;
				}
				pid_element_open = 1;
			}
			free(cmdline);
			/* Wipe current event since we are about to print a new PID. */
			memset(&cur_event, 0, sizeof(cur_event));
		}

		if (strcmp(cur_event.name, fields[i].event.name) != 0) {
			if (event_element_open) {
				/* Close the previous fields element and the previous event */
				ret = mi_lttng_close_multi_element(the_writer, 2);
				if (ret) {
					goto end;
				}
				event_element_open = 0;
			}

			memcpy(&cur_event, &fields[i].event, sizeof(cur_event));

			if (!event_element_open) {
				/* Open and write the event */
				ret = mi_lttng_event(
					the_writer, &cur_event, 1, the_handle->domain.type);
				if (ret) {
					goto end;
				}

				/* Open a fields element */
				ret = mi_lttng_event_fields_open(the_writer);
				if (ret) {
					goto end;
				}
				event_element_open = 1;
			}
		}

		/* Print the event_field */
		ret = mi_lttng_event_field(the_writer, &fields[i]);
		if (ret) {
			goto end;
		}
	}

	/* Close pids, domain, domains */
	ret = mi_lttng_close_multi_element(the_writer, 3);
end:
	return ret;
error:
	free(cmdline);
	return ret;
}

static int list_kernel_events(struct lttng_event *events, int count, struct lttng_domain *domain)
{
	int ret, i;

	/* Open domains element */
	ret = mi_lttng_domains_open(the_writer);
	if (ret) {
		goto end;
	}

	/* Write domain */
	ret = mi_lttng_domain(the_writer, domain, 1);
	if (ret) {
		goto end;
	}

	/* Open events */
	ret = mi_lttng_events_open(the_writer);
	if (ret) {
		goto end;
	}

	for (i = 0; i < count; i++) {
		ret = mi_lttng_event(the_writer, &events[i], 0, the_handle->domain.type);
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

static int list_syscalls(struct lttng_event *events, int count)
{
	int ret, i;

	/* Open events */
	ret = mi_lttng_events_open(the_writer);
	if (ret) {
		goto end;
	}

	for (i = 0; i < count; i++) {
		ret = mi_lttng_event(the_writer, &events[i], 0, the_handle->domain.type);
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

static int list_session_agent_events(struct lttng_event *events, int count)
{
	int ret, i;

	/* Open events element */
	ret = mi_lttng_events_open(the_writer);
	if (ret) {
		goto end;
	}

	for (i = 0; i < count; i++) {
		ret = mi_lttng_event(the_writer, &events[i], 0, the_handle->domain.type);
		if (ret) {
			goto end;
		}
	}

	/* Close events element */
	ret = mi_lttng_writer_close_element(the_writer);

end:
	return ret;
}

static int list_events(struct lttng_event *events, int count)
{
	int ret, i;

	/* Open events element */
	ret = mi_lttng_events_open(the_writer);
	if (ret) {
		goto end;
	}

	for (i = 0; i < count; i++) {
		ret = mi_lttng_event(the_writer, &events[i], 0, the_handle->domain.type);
		if (ret) {
			goto end;
		}
	}

	/* Close events element */
	ret = mi_lttng_writer_close_element(the_writer);

end:
	return ret;
}

static int write_channel_memory_usage(struct lttng_channel *channel)
{
	try {
		const auto channel_mem_usage = lcm::get_channel_memory_usage(
			the_handle->session_name, channel, the_handle->domain.type);

		return mi_lttng_data_stream_info_sets(
			the_writer,
			channel_mem_usage.data_stream_info_sets(),
			channel_mem_usage.data_stream_info_sets_count);
	} catch (const lttng::unsupported_error& e) {
		/* This information is not available for all domains. */
		return 0;
	} catch (const std::exception& e) {
		ERR_FMT("Failed to retrieve memory usage of channel `{}`: {}",
			channel->name,
			e.what());
		return -1;
	}
}

static int list_channels(struct lttng_channel *channels, int count, const char *channel_name)
{
	int i, ret;
	unsigned int chan_found = 0;

	/* Open channels element */
	ret = mi_lttng_channels_open(the_writer);
	if (ret) {
		goto error;
	}

	for (i = 0; i < count; i++) {
		if (channel_name != nullptr) {
			if (strncmp(channels[i].name, channel_name, NAME_MAX) == 0) {
				chan_found = 1;
			} else {
				continue;
			}
		}

		/* Write channel element  and leave it open */
		ret = mi_lttng_channel(the_writer, &channels[i], 1);
		if (ret) {
			goto error;
		}

		/* Listing events per channel */
		{
			int event_count;
			struct lttng_event *events = nullptr;

			event_count = lttng_list_events(the_handle, channels[i].name, &events);
			if (event_count < 0) {
				ret = CMD_ERROR;
				ERR("%s", lttng_strerror(event_count));
				goto error;
			}

			ret = list_events(events, event_count);
			free(events);
			if (ret) {
				goto error;
			}
		}

		/* Add memory usage, if available */
		ret = write_channel_memory_usage(&channels[i]);
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
 * Does not manage tracker handle lifecycle; caller handles cleanup on error.
 */
static int write_process_attr_values(enum lttng_process_attr process_attr,
				     const struct lttng_process_attr_values *values)
{
	int ret = CMD_SUCCESS;
	unsigned int val_count;
	enum lttng_process_attr_values_status values_status;

	values_status = lttng_process_attr_values_get_count(values, &val_count);
	if (values_status != LTTNG_PROCESS_ATTR_VALUES_STATUS_OK) {
		ERR("Failed to get value count");
		ret = CMD_ERROR;
		goto end;
	}

	for (unsigned int j = 0; j < val_count; j++) {
		const enum lttng_process_attr_value_type value_type =
			lttng_process_attr_values_get_type_at_index(values, j);

		if (value_type == LTTNG_PROCESS_ATTR_VALUE_TYPE_PID) {
			pid_t pid;
			values_status = lttng_process_attr_values_get_pid_at_index(values, j, &pid);
			if (values_status == LTTNG_PROCESS_ATTR_VALUES_STATUS_OK) {
				ret = mi_lttng_integral_process_attribute_value(
					the_writer, process_attr, (int64_t) pid, false);
			} else {
				ERR("Failed to get PID at index %u", j);
				ret = CMD_ERROR;
			}
		} else if (value_type == LTTNG_PROCESS_ATTR_VALUE_TYPE_UID) {
			uid_t uid;
			values_status = lttng_process_attr_values_get_uid_at_index(values, j, &uid);
			if (values_status == LTTNG_PROCESS_ATTR_VALUES_STATUS_OK) {
				ret = mi_lttng_integral_process_attribute_value(
					the_writer, process_attr, (int64_t) uid, false);
			} else {
				ERR("Failed to get UID at index %u", j);
				ret = CMD_ERROR;
			}
		} else if (value_type == LTTNG_PROCESS_ATTR_VALUE_TYPE_GID) {
			gid_t gid;
			values_status = lttng_process_attr_values_get_gid_at_index(values, j, &gid);
			if (values_status == LTTNG_PROCESS_ATTR_VALUES_STATUS_OK) {
				ret = mi_lttng_integral_process_attribute_value(
					the_writer, process_attr, (int64_t) gid, false);
			} else {
				ERR("Failed to get GID at index %u", j);
				ret = CMD_ERROR;
			}
		} else if (value_type == LTTNG_PROCESS_ATTR_VALUE_TYPE_USER_NAME) {
			const char *name;
			values_status =
				lttng_process_attr_values_get_user_name_at_index(values, j, &name);
			if (values_status == LTTNG_PROCESS_ATTR_VALUES_STATUS_OK) {
				ret = mi_lttng_string_process_attribute_value(
					the_writer, process_attr, name, false);
			} else {
				ERR("Failed to get user name at index %u", j);
				ret = CMD_ERROR;
			}
		} else if (value_type == LTTNG_PROCESS_ATTR_VALUE_TYPE_GROUP_NAME) {
			const char *name;
			values_status =
				lttng_process_attr_values_get_group_name_at_index(values, j, &name);
			if (values_status == LTTNG_PROCESS_ATTR_VALUES_STATUS_OK) {
				ret = mi_lttng_string_process_attribute_value(
					the_writer, process_attr, name, false);
			} else {
				ERR("Failed to get group name at index %u", j);
				ret = CMD_ERROR;
			}
		}

		if (ret) {
			goto end;
		}
	}

end:
	return ret;
}

static int list_session(const char *session_name, struct lttng_session *sessions, int count)
{
	int ret, i;
	bool session_found = false;

	if (session_name == nullptr) {
		ret = -LTTNG_ERR_SESS_NOT_FOUND;
		goto end;
	}

	for (i = 0; i < count; i++) {
		if (strncmp(sessions[i].name, session_name, NAME_MAX) == 0) {
			/*
			 * We need to leave it open to append other informations
			 * like domain, channel, events etc.
			 */
			session_found = true;
			ret = mi_lttng_session(the_writer, &sessions[i], 1);
			if (ret) {
				goto end;
			}
			break;
		}
	}

	if (!session_found) {
		ERR("Session '%s' not found", session_name);
		ret = -LTTNG_ERR_SESS_NOT_FOUND;
		goto end;
	}

end:
	return ret;
}

static int list_sessions(struct lttng_session *sessions, int count)
{
	int ret, i;

	/* Opening sessions element */
	ret = mi_lttng_sessions_open(the_writer);
	if (ret) {
		goto end;
	}

	/* Listing sessions */
	for (i = 0; i < count; i++) {
		ret = mi_lttng_session(the_writer, &sessions[i], 0);
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

/*
 * Write the trackers for a given domain and session to the MI writer.
 */
static int write_domain_trackers(const char *session_name, const struct lttng_domain *domain)
{
	int ret = CMD_SUCCESS;

	/* Trackers */
	ret = mi_lttng_trackers_open(the_writer);
	if (ret) {
		goto end;
	}

	/* Output trackers for this domain */
	{
		enum lttng_process_attr process_attrs[] = {
			LTTNG_PROCESS_ATTR_PROCESS_ID, LTTNG_PROCESS_ATTR_VIRTUAL_PROCESS_ID,
			LTTNG_PROCESS_ATTR_USER_ID,    LTTNG_PROCESS_ATTR_VIRTUAL_USER_ID,
			LTTNG_PROCESS_ATTR_GROUP_ID,   LTTNG_PROCESS_ATTR_VIRTUAL_GROUP_ID,
		};
		size_t num_attrs = sizeof(process_attrs) / sizeof(process_attrs[0]);

		for (size_t i = 0; i < num_attrs; i++) {
			enum lttng_process_attr process_attr = process_attrs[i];
			const struct lttng_process_attr_values *values;
			struct lttng_process_attr_tracker_handle *tracker_handle = nullptr;
			enum lttng_error_code ret_code;
			enum lttng_process_attr_tracker_handle_status handle_status;
			enum lttng_tracking_policy policy;

			/* Skip attributes not applicable to this domain */
			if (domain->type == LTTNG_DOMAIN_UST) {
				if (process_attr == LTTNG_PROCESS_ATTR_PROCESS_ID ||
				    process_attr == LTTNG_PROCESS_ATTR_USER_ID ||
				    process_attr == LTTNG_PROCESS_ATTR_GROUP_ID) {
					continue;
				}
			}

			ret_code = lttng_session_get_tracker_handle(
				session_name, domain->type, process_attr, &tracker_handle);
			if (ret_code != LTTNG_OK) {
				ERR("Failed to get process attribute tracker handle: %s",
				    lttng_strerror(ret_code));
				ret = CMD_ERROR;
				goto close_trackers;
			}

			handle_status = lttng_process_attr_tracker_handle_get_tracking_policy(
				tracker_handle, &policy);
			ret = handle_process_attr_status(process_attr, handle_status, session_name);
			if (ret != CMD_SUCCESS) {
				lttng_process_attr_tracker_handle_destroy(tracker_handle);
				goto close_trackers;
			}

			handle_status = lttng_process_attr_tracker_handle_get_inclusion_set(
				tracker_handle, &values);
			ret = handle_process_attr_status(process_attr, handle_status, session_name);
			if (ret != CMD_SUCCESS) {
				lttng_process_attr_tracker_handle_destroy(tracker_handle);
				goto close_trackers;
			}

			if (policy == LTTNG_TRACKING_POLICY_EXCLUDE_ALL) {
				ret = output_empty_tracker(process_attr);
				lttng_process_attr_tracker_handle_destroy(tracker_handle);
				if (ret) {
					goto close_trackers;
				}
				continue;
			}

			if (policy == LTTNG_TRACKING_POLICY_INCLUDE_ALL) {
				/* Skip - all is implicit */
				lttng_process_attr_tracker_handle_destroy(tracker_handle);
				continue;
			}

			/* INCLUDE_SET - output tracker */
			ret = mi_lttng_process_attribute_tracker_open(the_writer, process_attr);
			if (ret) {
				lttng_process_attr_tracker_handle_destroy(tracker_handle);
				goto close_trackers;
			}

			/* Output values */
			ret = write_process_attr_values(process_attr, values);
			if (ret) {
				lttng_process_attr_tracker_handle_destroy(tracker_handle);
				goto close_trackers;
			}

			/* Close tracker element */
			ret = mi_lttng_close_multi_element(the_writer, 2);
			lttng_process_attr_tracker_handle_destroy(tracker_handle);
			if (ret) {
				goto close_trackers;
			}
		}
	}

	/* Close trackers element */
	ret = mi_lttng_writer_close_element(the_writer);
	if (ret) {
		goto end;
	}

	goto end;

close_trackers:
{
	int close_ret = mi_lttng_writer_close_element(the_writer);
	(void) close_ret; /* Best-effort close; preserve original error. */
}
end:
	return ret;
}

static int list_domains(struct lttng_domain *domains, int count)
{
	int i, ret;
	/* Open domains element */
	ret = mi_lttng_domains_open(the_writer);
	if (ret) {
		goto end;
	}

	for (i = 0; i < count; i++) {
		ret = mi_lttng_domain(the_writer, &domains[i], 0);
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
static int handle_no_session_name(struct lttng_domain *domain)
{
	int ret = CMD_SUCCESS;

	/* Listing sessions, kernel/ust events, or syscalls */
	if (!opt_kernel && !opt_userspace && !opt_jul && !opt_log4j && !opt_log4j2 && !opt_python) {
		/* List all sessions */
		struct lttng_session *sessions = nullptr;
		int count = lttng_list_sessions(&sessions);
		DBG("Session count %d", count);
		if (count < 0) {
			ret = CMD_ERROR;
			ERR("%s", lttng_strerror(count));
			goto end;
		}
		ret = list_sessions(sessions, count);
		free(sessions);
		if (ret) {
			ret = CMD_ERROR;
			goto end;
		}
	}

	if (opt_kernel) {
		struct lttng_event *event_list;
		int size;

		if (opt_syscall) {
			/* List syscalls */
			size = lttng_list_syscalls(&event_list);
			if (size < 0) {
				ERR("Unable to list system calls: %s", lttng_strerror(size));
				ret = CMD_ERROR;
				goto end;
			}
			ret = list_syscalls(event_list, size);
			free(event_list);
			if (ret) {
				ret = CMD_ERROR;
				goto end;
			}
		} else {
			/* List kernel events */
			size = lttng_list_tracepoints(the_handle, &event_list);
			if (size < 0) {
				ERR("Unable to list kernel events: %s", lttng_strerror(size));
				ret = CMD_ERROR;
				goto end;
			}
			ret = list_kernel_events(event_list, size, domain);
			free(event_list);
			if (ret) {
				ret = CMD_ERROR;
				goto end;
			}
		}
	}

	if (opt_userspace) {
		if (opt_fields) {
			/* List UST event fields */
			struct lttng_event_field *event_field_list;
			int size = lttng_list_tracepoint_fields(the_handle, &event_field_list);
			if (size < 0) {
				ERR("Unable to list UST event fields: %s", lttng_strerror(size));
				ret = CMD_ERROR;
				goto end;
			}
			ret = list_ust_event_fields(event_field_list, size, domain);
			free(event_field_list);
			if (ret) {
				ret = CMD_ERROR;
				goto end;
			}
		} else {
			/* List UST events */
			struct lttng_event *event_list;
			int size = lttng_list_tracepoints(the_handle, &event_list);
			if (size < 0) {
				ERR("Unable to list UST events: %s", lttng_strerror(size));
				ret = CMD_ERROR;
				goto end;
			}
			ret = list_agent_ust_events(event_list, size, domain);
			free(event_list);
			if (ret) {
				ret = CMD_ERROR;
				goto end;
			}
		}
	}

	if (opt_jul || opt_log4j || opt_log4j2 || opt_python) {
		/* List agent events */
		struct lttng_event *event_list;
		int size = lttng_list_tracepoints(the_handle, &event_list);
		if (size < 0) {
			const char *agent_domain_str = lttng_domain_type_str(domain->type);
			ERR("Unable to list %s events: %s", agent_domain_str, lttng_strerror(size));
			ret = CMD_ERROR;
			goto end;
		}
		ret = list_agent_ust_events(event_list, size, domain);
		free(event_list);
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
static int write_session_rotation_schedules(const char *session_name)
{
	int ret = CMD_SUCCESS;
	unsigned int sched_count;
	struct lttng_rotation_schedules *schedules = nullptr;
	enum lttng_rotation_status status;
	int ret_code;

	ret_code = lttng_session_list_rotation_schedules(session_name, &schedules);
	if (ret_code != LTTNG_OK) {
		ERR("Failed to list session rotation schedules: %s", lttng_strerror(ret_code));
		ret = CMD_ERROR;
		goto end;
	}

	status = lttng_rotation_schedules_get_count(schedules, &sched_count);
	if (status != LTTNG_ROTATION_STATUS_OK) {
		ERR("Failed to retrieve the number of session rotation schedules.");
		ret = CMD_ERROR;
		goto destroy;
	}

	if (sched_count > 0) {
		ret = mi_lttng_writer_open_element(the_writer, mi_lttng_element_rotation_schedules);
		if (ret) {
			ret = CMD_ERROR;
			goto destroy;
		}

		for (unsigned int i = 0; i < sched_count; i++) {
			const struct lttng_rotation_schedule *schedule;

			schedule = lttng_rotation_schedules_get_at_index(schedules, i);
			if (!schedule) {
				ERR("Failed to retrieve session rotation schedule.");
				ret = CMD_ERROR;
				goto destroy;
			}

			ret = mi_lttng_rotation_schedule(the_writer, schedule);
			if (ret) {
				ret = CMD_ERROR;
				goto destroy;
			}
		}

		/* Close rotation_schedules element */
		ret = mi_lttng_writer_close_element(the_writer);
		if (ret) {
			ret = CMD_ERROR;
			goto destroy;
		}
	}

destroy:
	lttng_rotation_schedules_destroy(schedules);
end:
	return ret;
}

/*
 * List all domains of a session, including trackers and channels, and emit
 * them to the MI writer. This function opens and closes the `domains` MI
 * element internally and leaves the surrounding `session`/`sessions` elements
 * to the caller.
 */
static int list_all_session_domains(const char *session_name)
{
	int ret = CMD_SUCCESS;
	struct lttng_domain *domains_local = nullptr;
	int nb_domain;

	nb_domain = lttng_list_domains(session_name, &domains_local);
	if (nb_domain < 0) {
		ret = CMD_ERROR;
		ERR("%s", lttng_strerror(nb_domain));
		goto end;
	}

	ret = mi_lttng_domains_open(the_writer);
	if (ret) {
		ret = CMD_ERROR;
		goto end;
	}

	for (int i = 0; i < nb_domain; i++) {
		struct lttng_channel *channels = nullptr;
		int channel_count;

		ret = mi_lttng_domain(the_writer, &domains_local[i], 1);
		if (ret) {
			ret = CMD_ERROR;
			goto close_domains_element;
		}

		/* Clean handle before creating a new one */
		if (the_handle) {
			lttng_destroy_handle(the_handle);
		}

		the_handle = lttng_create_handle(session_name, &domains_local[i]);
		if (the_handle == nullptr) {
			ret = CMD_FATAL;
			goto close_domains_element;
		}

		if (domains_local[i].type == LTTNG_DOMAIN_JUL ||
		    domains_local[i].type == LTTNG_DOMAIN_LOG4J ||
		    domains_local[i].type == LTTNG_DOMAIN_LOG4J2 ||
		    domains_local[i].type == LTTNG_DOMAIN_PYTHON) {
			/* List agent events */
			struct lttng_event *events = nullptr;
			int count;

			count = lttng_list_events(the_handle, "", &events);
			if (count < 0) {
				ret = CMD_ERROR;
				ERR("%s", lttng_strerror(count));
				free(events);
				goto close_domain_element;
			}

			ret = list_session_agent_events(events, count);
			free(events);
			if (ret) {
				ret = CMD_ERROR;
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
		if (domains_local[i].type == LTTNG_DOMAIN_KERNEL ||
		    domains_local[i].type == LTTNG_DOMAIN_UST) {
			ret = write_domain_trackers(session_name, &domains_local[i]);
			if (ret) {
				goto close_domain_element;
			}
		}

		/* List channels */
		channel_count = lttng_list_channels(the_handle, &channels);
		if (channel_count < 0) {
			ret = CMD_ERROR;
			ERR("%s", lttng_strerror(channel_count));
			goto close_domain_element;
		}

		ret = list_channels(channels, channel_count, opt_channel);
		free(channels);
		if (ret) {
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
	free(domains_local);
	return ret;
}

/*
 * Handle MI listing when a session name is provided.
 */
static int handle_with_session_name(const char *session_name, struct lttng_domain *domain)
{
	int ret = CMD_SUCCESS;
	struct lttng_domain *domains = nullptr;

	/* List session attributes */
	{
		struct lttng_session *sessions = nullptr;
		int count = lttng_list_sessions(&sessions);
		DBG("Session count %d", count);
		if (count < 0) {
			ret = CMD_ERROR;
			ERR("%s", lttng_strerror(count));
			goto end;
		}

		/* Open sessions element */
		ret = mi_lttng_sessions_open(the_writer);
		if (ret) {
			free(sessions);
			goto end;
		}

		/* List the session */
		ret = list_session(session_name, sessions, count);
		free(sessions);
		if (ret) {
			goto end;
		}
	}

	/* Automatic rotation schedules */
	ret = write_session_rotation_schedules(session_name);
	if (ret) {
		goto end;
	}

	/* Domain listing */
	if (opt_domain) {
		int nb_domain = lttng_list_domains(session_name, &domains);
		if (nb_domain < 0) {
			ret = CMD_ERROR;
			ERR("%s", lttng_strerror(nb_domain));
			goto end;
		}
		ret = list_domains(domains, nb_domain);
		free(domains);
		domains = nullptr;
		goto end;
	}

	/* Channel listing */
	if (opt_kernel || opt_userspace) {
		struct lttng_channel *channels = nullptr;
		int channel_count;

		/* Add domains and domain element */
		ret = mi_lttng_domains_open(the_writer);
		if (ret) {
			goto end;
		}

		/* Open domain and leave it open for nested elements */
		ret = mi_lttng_domain(the_writer, domain, 1);
		if (ret) {
			goto end;
		}

		/* Trackers */
		ret = write_domain_trackers(session_name, domain);
		if (ret) {
			goto end;
		}

		/* Channels */
		channel_count = lttng_list_channels(the_handle, &channels);
		if (channel_count < 0) {
			ret = CMD_ERROR;
			ERR("%s", lttng_strerror(channel_count));
			goto end;
		}

		ret = list_channels(channels, channel_count, opt_channel);
		free(channels);
		if (ret) {
			goto end;
		}

		/* Close domain element */
		ret = mi_lttng_writer_close_element(the_writer);
		if (ret) {
			ret = CMD_ERROR;
			goto end;
		}

		/* Close the domains, session and sessions element */
		ret = mi_lttng_close_multi_element(the_writer, 3);
		if (ret) {
			ret = CMD_ERROR;
			goto end;
		}

		goto end;
	}

	/* List all domains */
	ret = list_all_session_domains(session_name);
	if (ret) {
		goto end;
	}

	/* Close the session and sessions element */
	ret = mi_lttng_close_multi_element(the_writer, 2);
	if (ret) {
		ret = CMD_ERROR;
		goto end;
	}

end:
	free(domains);
	return ret;
}

/*
 * Entry point for machine interface list command.
 */
int list_mi(const char *session_name,
	    int opt_kernel_param,
	    int opt_userspace_param,
	    int opt_jul_param,
	    int opt_log4j_param,
	    int opt_log4j2_param,
	    int opt_python_param,
	    const char *opt_channel_param,
	    int opt_domain_param,
	    int opt_fields_param,
	    int opt_syscall_param)
{
	int ret = CMD_SUCCESS;
	struct lttng_domain domain;
	struct lttng_domain *domains = nullptr;

	memset(&domain, 0, sizeof(domain));

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

	/* Determine domain type */
	if (opt_kernel_param) {
		domain.type = LTTNG_DOMAIN_KERNEL;
	} else if (opt_userspace_param) {
		DBG2("Listing userspace global domain");
		domain.type = LTTNG_DOMAIN_UST;
	} else if (opt_jul_param) {
		DBG2("Listing JUL domain");
		domain.type = LTTNG_DOMAIN_JUL;
	} else if (opt_log4j_param) {
		domain.type = LTTNG_DOMAIN_LOG4J;
	} else if (opt_log4j2_param) {
		domain.type = LTTNG_DOMAIN_LOG4J2;
	} else if (opt_python_param) {
		domain.type = LTTNG_DOMAIN_PYTHON;
	}

	if (opt_kernel_param || opt_userspace_param || opt_jul_param || opt_log4j_param ||
	    opt_log4j2_param || opt_python_param) {
		the_handle = lttng_create_handle(session_name, &domain);
		if (the_handle == nullptr) {
			ret = CMD_FATAL;
			goto end;
		}
	}

	/* Cache options for use by helpers. */
	opt_kernel = opt_kernel_param;
	opt_userspace = opt_userspace_param;
	opt_jul = opt_jul_param;
	opt_log4j = opt_log4j_param;
	opt_log4j2 = opt_log4j2_param;
	opt_python = opt_python_param;
	opt_channel = opt_channel_param;
	opt_domain = opt_domain_param;
	opt_fields = opt_fields_param;
	opt_syscall = opt_syscall_param;

	if (!session_name) {
		ret = handle_no_session_name(&domain);
	} else {
		ret = handle_with_session_name(session_name, &domain);
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

	free(domains);
	if (the_handle) {
		lttng_destroy_handle(the_handle);
	}

	return ret;
}
