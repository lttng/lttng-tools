/*
 * SPDX-FileCopyrightText: 2011 EfficiOS Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#define _LGPL_SOURCE
#include "condition-internal.hpp"
#include "consumer.hpp"
#include "event-notifier-error-accounting.hpp"
#include "kern-modules.hpp"
#include "kernel.hpp"
#include "lttng-sessiond.hpp"
#include "lttng-syscall.hpp"
#include "modprobe.hpp"
#include "notification-thread-commands.hpp"
#include "sessiond-config.hpp"
#include "utils.hpp"

#include <common/common.hpp>
#include <common/hashtable/utils.hpp>
#include <common/kernel-ctl/kernel-ctl.hpp>
#include <common/kernel-ctl/kernel-ioctl.hpp>
#include <common/scope-exit.hpp>
#include <common/sessiond-comm/sessiond-comm.hpp>
#include <common/trace-chunk.hpp>
#include <common/urcu.hpp>
#include <common/utils.hpp>

#include <lttng/condition/event-rule-matches-internal.hpp>
#include <lttng/condition/event-rule-matches.h>
#include <lttng/event-rule/event-rule-internal.hpp>
#include <lttng/event-rule/event-rule.h>
#include <lttng/event-rule/kernel-uprobe-internal.hpp>
#include <lttng/event.h>
#include <lttng/lttng-error.h>
#include <lttng/userspace-probe-internal.hpp>
#include <lttng/userspace-probe.h>

#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

namespace ls = lttng::sessiond::config;

/*
 * Convert a channel_configuration to the lttng_kernel_abi_channel struct
 * expected by the kernel tracer ioctls.
 *
 * This is used by the modules domain orchestrator for channel creation and
 * internally for metadata and snapshot operations.
 */
lttng_kernel_abi_channel make_kernel_abi_channel(const ls::channel_configuration& channel_config)
{
	lttng_kernel_abi_channel kernel_channel = {};

	kernel_channel.overwrite = channel_config.buffer_full_policy ==
			ls::channel_configuration::buffer_full_policy_t::OVERWRITE_OLDEST_PACKET ?
		1 :
		0;
	kernel_channel.subbuf_size = channel_config.subbuffer_size_bytes;
	kernel_channel.num_subbuf = channel_config.subbuffer_count;
	kernel_channel.switch_timer_interval = channel_config.switch_timer_period_us.value_or(0);
	kernel_channel.read_timer_interval = channel_config.read_timer_period_us.value_or(0);
	kernel_channel.output = channel_config.buffer_consumption_backend ==
			ls::channel_configuration::buffer_consumption_backend_t::MMAP ?
		LTTNG_EVENT_MMAP :
		LTTNG_EVENT_SPLICE;

	return kernel_channel;
}

namespace {
/*
 * Key used to reference a channel between the sessiond and the consumer. This
 * is only read and updated with the session_list lock held.
 */
uint64_t next_kernel_channel_key;

const char *module_proc_lttng = "/proc/lttng";

int kernel_tracer_fd = -1;
nonstd::optional<enum lttng_kernel_tracer_status> kernel_tracer_status = nonstd::nullopt;
int kernel_tracer_event_notifier_group_fd = -1;
int kernel_tracer_event_notifier_group_notification_fd = -1;
bool kernel_tracer_event_notifier_group_notification_fd_registered = false;
struct cds_lfht *kernel_token_to_event_notifier_rule_ht;

const char *kernel_tracer_status_to_str(lttng_kernel_tracer_status status)
{
	switch (status) {
	case LTTNG_KERNEL_TRACER_STATUS_INITIALIZED:
		return "LTTNG_KERNEL_TRACER_STATUS_INITIALIZED";
	case LTTNG_KERNEL_TRACER_STATUS_ERR_UNKNOWN:
		return "LTTNG_KERNEL_TRACER_STATUS_ERR_UNKNOWN";
	case LTTNG_KERNEL_TRACER_STATUS_ERR_NEED_ROOT:
		return "LTTNG_KERNEL_TRACER_STATUS_ERR_NEED_ROOT";
	case LTTNG_KERNEL_TRACER_STATUS_ERR_NOTIFIER:
		return "LTTNG_KERNEL_TRACER_STATUS_ERR_NOTIFIER";
	case LTTNG_KERNEL_TRACER_STATUS_ERR_OPEN_PROC_LTTNG:
		return "LTTNG_KERNEL_TRACER_STATUS_ERR_OPEN_PROC_LTTNG";
	case LTTNG_KERNEL_TRACER_STATUS_ERR_VERSION_MISMATCH:
		return "LTTNG_KERNEL_TRACER_STATUS_ERR_VERSION_MISMATCH";
	case LTTNG_KERNEL_TRACER_STATUS_ERR_MODULES_UNKNOWN:
		return "LTTNG_KERNEL_TRACER_STATUS_ERR_MODULES_UNKNOWN";
	case LTTNG_KERNEL_TRACER_STATUS_ERR_MODULES_MISSING:
		return "LTTNG_KERNEL_TRACER_STATUS_ERR_MODULES_MISSING";
	case LTTNG_KERNEL_TRACER_STATUS_ERR_MODULES_SIGNATURE:
		return "LTTNG_KERNEL_TRACER_STATUS_ERR_MODULES_SIGNATURE";
	}

	abort();
}

/*
 * On some architectures, calling convention details are embedded in the symbol
 * addresses. Uprobe requires a "clean" symbol offset (or at least, an address
 * where an instruction boundary would be legal) to add
 * instrumentation. sanitize_uprobe_offset implements that sanitization logic on
 * a per-architecture basis.
 */
#if defined(__arm__) || defined(__aarch64__)
static inline uint64_t sanitize_uprobe_offset(uint64_t raw_offset)
{
	/*
	 * The least significant bit is used when branching to switch to thumb
	 * ISA. However, it's an invalid address for us; mask the least
	 * significant bit.
	 */
	return raw_offset &= ~0b1;
}
#else /* defined(__arm__) || defined(__aarch64__) */
inline uint64_t sanitize_uprobe_offset(uint64_t raw_offset)
{
	return raw_offset;
}
#endif
} /* namespace */

uint64_t allocate_next_kernel_stream_group_key()
{
	return ++next_kernel_channel_key;
}

/*
 * Create a new kernel session, register it to the kernel tracer and add it to
 * the session daemon session.
 */
int kernel_create_session(const ltt_session::locked_ref& session)
{
	int ret;
	struct ltt_kernel_session *lks;

	/* Allocate data structure */
	lks = trace_kernel_create_session();
	if (lks == nullptr) {
		ret = -1;
		goto error;
	}

	/* Kernel tracer session creation */
	ret = kernctl_create_session(kernel_tracer_fd);
	if (ret < 0) {
		PERROR("ioctl kernel create session");
		goto error;
	}

	lks->fd = ret;
	/* Prevent fd duplication after execlp() */
	ret = fcntl(lks->fd, F_SETFD, FD_CLOEXEC);
	if (ret < 0) {
		PERROR("fcntl session fd");
	}

	lks->id = session->id;
	lks->consumer_fds_sent = 0;
	session->kernel_session = lks;

	DBG("Kernel session created (fd: %d)", lks->fd);

	/*
	 * This is necessary since the creation time is present in the session
	 * name when it is generated.
	 */
	if (session->has_auto_generated_name) {
		ret = kernctl_session_set_name(lks->fd, DEFAULT_SESSION_NAME);
	} else {
		ret = kernctl_session_set_name(lks->fd, session->name);
	}
	if (ret) {
		WARN("Could not set kernel session name for session %" PRIu64 " name: %s",
		     session->id,
		     session->name);
	}

	ret = kernctl_session_set_creation_time(lks->fd, session->creation_time);
	if (ret) {
		WARN("Could not set kernel session creation time for session %" PRIu64 " name: %s",
		     session->id,
		     session->name);
	}

	ret = kernctl_session_set_output_format(lks->fd,
						session->trace_format == LTTNG_TRACE_FORMAT_CTF_2 ?
							LTTNG_KERNEL_ABI_OUTPUT_FORMAT_CTF_2 :
							LTTNG_KERNEL_ABI_OUTPUT_FORMAT_CTF_1_8);
	if (ret) {
		if (ret == -ENOSYS && session->trace_format == LTTNG_TRACE_FORMAT_CTF_2) {
			ERR("Kernel tracer does not support CTF 2 trace format for session %" PRIu64
			    " name: %s",
			    session->id,
			    session->name);
			goto error;
		}
		WARN_FMT("Could not set kernel output format for session {} name: {}",
			 session->id,
			 session->name);
	}

	return 0;

error:
	if (lks) {
		trace_kernel_destroy_session(lks);
		trace_kernel_free_session(lks);
	}
	return ret;
}

/*
 * Create a kernel event notifier group, register it to the kernel tracer and
 * add it to the kernel session.
 */
static int kernel_create_event_notifier_group(int *event_notifier_group_fd)
{
	int ret;
	int local_fd = -1;

	LTTNG_ASSERT(event_notifier_group_fd);

	/* Kernel event notifier group creation. */
	ret = kernctl_create_event_notifier_group(kernel_tracer_fd);
	if (ret < 0) {
		PERROR("Failed to create kernel event notifier group");
		ret = -1;
		goto error;
	}

	local_fd = ret;

	/* Prevent fd duplication after execlp(). */
	ret = fcntl(local_fd, F_SETFD, FD_CLOEXEC);
	if (ret < 0) {
		PERROR("Failed to set FD_CLOEXEC on kernel event notifier group file descriptor: fd = %d",
		       local_fd);
		goto error;
	}

	DBG("Created kernel event notifier group: fd = %d", local_fd);
	*event_notifier_group_fd = local_fd;
	local_fd = -1;
	ret = 0;
error:
	if (local_fd >= 0) {
		ret = close(local_fd);
		if (ret) {
			PERROR("Failed to close kernel event notifier group file descriptor: fd = %d",
			       local_fd);
		}
	}

	return ret;
}

/*
 * Compute the offset of the instrumentation byte in the binary based on the
 * function probe location using the ELF lookup method.
 *
 * Returns 0 on success and set the offset out parameter to the offset of the
 * elf symbol
 * Returns -1 on error
 */
static int extract_userspace_probe_offset_function_elf(
	const struct lttng_userspace_probe_location *probe_location,
	uid_t uid,
	gid_t gid,
	uint64_t *offset)
{
	int fd;
	int ret = 0;
	const char *symbol = nullptr;
	const struct lttng_userspace_probe_location_lookup_method *lookup = nullptr;
	enum lttng_userspace_probe_location_lookup_method_type lookup_method_type;

	LTTNG_ASSERT(lttng_userspace_probe_location_get_type(probe_location) ==
		     LTTNG_USERSPACE_PROBE_LOCATION_TYPE_FUNCTION);

	lookup = lttng_userspace_probe_location_get_lookup_method(probe_location);
	if (!lookup) {
		ret = -1;
		goto end;
	}

	lookup_method_type = lttng_userspace_probe_location_lookup_method_get_type(lookup);

	LTTNG_ASSERT(lookup_method_type ==
		     LTTNG_USERSPACE_PROBE_LOCATION_LOOKUP_METHOD_TYPE_FUNCTION_ELF);

	symbol = lttng_userspace_probe_location_function_get_function_name(probe_location);
	if (!symbol) {
		ret = -1;
		goto end;
	}

	fd = lttng_userspace_probe_location_function_get_binary_fd(probe_location);
	if (fd < 0) {
		ret = -1;
		goto end;
	}

	ret = run_as_extract_elf_symbol_offset(fd, symbol, uid, gid, offset);
	if (ret < 0) {
		DBG("userspace probe offset calculation failed for "
		    "function %s",
		    symbol);
		goto end;
	}

	DBG("userspace probe elf offset for %s is 0x%jd", symbol, (intmax_t) (*offset));
end:
	return ret;
}

/*
 * Compute the offsets of the instrumentation bytes in the binary based on the
 * tracepoint probe location using the SDT lookup method. This function
 * allocates the offsets buffer, the caller must free it.
 *
 * Returns 0 on success and set the offset out parameter to the offsets of the
 * SDT tracepoint.
 * Returns -1 on error.
 */
static int extract_userspace_probe_offset_tracepoint_sdt(
	const struct lttng_userspace_probe_location *probe_location,
	uid_t uid,
	gid_t gid,
	uint64_t **offsets,
	uint32_t *offsets_count)
{
	enum lttng_userspace_probe_location_lookup_method_type lookup_method_type;
	const struct lttng_userspace_probe_location_lookup_method *lookup = nullptr;
	const char *probe_name = nullptr, *provider_name = nullptr;
	int ret = 0;
	int fd, i;

	LTTNG_ASSERT(lttng_userspace_probe_location_get_type(probe_location) ==
		     LTTNG_USERSPACE_PROBE_LOCATION_TYPE_TRACEPOINT);

	lookup = lttng_userspace_probe_location_get_lookup_method(probe_location);
	if (!lookup) {
		ret = -1;
		goto end;
	}

	lookup_method_type = lttng_userspace_probe_location_lookup_method_get_type(lookup);

	LTTNG_ASSERT(lookup_method_type ==
		     LTTNG_USERSPACE_PROBE_LOCATION_LOOKUP_METHOD_TYPE_TRACEPOINT_SDT);

	probe_name = lttng_userspace_probe_location_tracepoint_get_probe_name(probe_location);
	if (!probe_name) {
		ret = -1;
		goto end;
	}

	provider_name = lttng_userspace_probe_location_tracepoint_get_provider_name(probe_location);
	if (!provider_name) {
		ret = -1;
		goto end;
	}

	fd = lttng_userspace_probe_location_tracepoint_get_binary_fd(probe_location);
	if (fd < 0) {
		ret = -1;
		goto end;
	}

	ret = run_as_extract_sdt_probe_offsets(
		fd, provider_name, probe_name, uid, gid, offsets, offsets_count);
	if (ret < 0) {
		DBG("userspace probe offset calculation failed for sdt "
		    "probe %s:%s",
		    provider_name,
		    probe_name);
		goto end;
	}

	if (*offsets_count == 0) {
		DBG("no userspace probe offset found");
		goto end;
	}

	DBG("%u userspace probe SDT offsets found for %s:%s at:",
	    *offsets_count,
	    provider_name,
	    probe_name);
	for (i = 0; i < *offsets_count; i++) {
		DBG("\t0x%jd", (intmax_t) ((*offsets)[i]));
	}
end:
	return ret;
}

static int userspace_probe_add_callsite(const struct lttng_userspace_probe_location *location,
					uid_t uid,
					gid_t gid,
					int fd)
{
	const struct lttng_userspace_probe_location_lookup_method *lookup_method = nullptr;
	enum lttng_userspace_probe_location_lookup_method_type type;
	int ret;

	lookup_method = lttng_userspace_probe_location_get_lookup_method(location);
	if (!lookup_method) {
		ret = -1;
		goto end;
	}

	type = lttng_userspace_probe_location_lookup_method_get_type(lookup_method);
	switch (type) {
	case LTTNG_USERSPACE_PROBE_LOCATION_LOOKUP_METHOD_TYPE_FUNCTION_ELF:
	{
		struct lttng_kernel_abi_event_callsite callsite;
		uint64_t offset;

		ret = extract_userspace_probe_offset_function_elf(location, uid, gid, &offset);
		if (ret) {
			ret = LTTNG_ERR_PROBE_LOCATION_INVAL;
			goto end;
		}

		callsite.u.uprobe.offset = sanitize_uprobe_offset(offset);
		ret = kernctl_add_callsite(fd, &callsite);
		if (ret) {
			WARN("Failed to add callsite to ELF userspace probe.");
			ret = LTTNG_ERR_KERN_ENABLE_FAIL;
			goto end;
		}
		break;
	}
	case LTTNG_USERSPACE_PROBE_LOCATION_LOOKUP_METHOD_TYPE_TRACEPOINT_SDT:
	{
		int i;
		uint64_t *offsets = nullptr;
		uint32_t offsets_count;
		struct lttng_kernel_abi_event_callsite callsite;

		/*
		 * This call allocates the offsets buffer. This buffer must be freed
		 * by the caller
		 */
		ret = extract_userspace_probe_offset_tracepoint_sdt(
			location, uid, gid, &offsets, &offsets_count);
		if (ret) {
			ret = LTTNG_ERR_PROBE_LOCATION_INVAL;
			goto end;
		}
		for (i = 0; i < offsets_count; i++) {
			callsite.u.uprobe.offset = sanitize_uprobe_offset(offsets[i]);
			ret = kernctl_add_callsite(fd, &callsite);
			if (ret) {
				WARN("Failed to add callsite to SDT userspace probe");
				ret = LTTNG_ERR_KERN_ENABLE_FAIL;
				free(offsets);
				goto end;
			}
		}
		free(offsets);
		break;
	}
	default:
		ret = LTTNG_ERR_PROBE_LOCATION_INVAL;
		goto end;
	}
end:
	return ret;
}

/*
 * Extract the offsets of the instrumentation point for the different look-up
 * methods.
 */
int userspace_probe_event_rule_add_callsites(const struct lttng_event_rule *rule,
					     const struct lttng_credentials *creds,
					     int fd)
{
	int ret;
	enum lttng_event_rule_status status;
	enum lttng_event_rule_type event_rule_type;
	const struct lttng_userspace_probe_location *location = nullptr;

	LTTNG_ASSERT(rule);
	LTTNG_ASSERT(creds);

	event_rule_type = lttng_event_rule_get_type(rule);
	LTTNG_ASSERT(event_rule_type == LTTNG_EVENT_RULE_TYPE_KERNEL_UPROBE);

	status = lttng_event_rule_kernel_uprobe_get_location(rule, &location);
	if (status != LTTNG_EVENT_RULE_STATUS_OK || !location) {
		ret = -1;
		goto end;
	}

	ret = userspace_probe_add_callsite(
		location, lttng_credentials_get_uid(creds), lttng_credentials_get_gid(creds), fd);
	if (ret) {
		WARN("Failed to add callsite to user space probe object: fd = %d", fd);
	}

end:
	return ret;
}

/*
 * Disable a kernel event notifier.
 */
static int kernel_disable_event_notifier_rule(struct ltt_kernel_event_notifier_rule *event)
{
	int ret;

	LTTNG_ASSERT(event);

	const lttng::urcu::read_lock_guard read_lock;
	cds_lfht_del(kernel_token_to_event_notifier_rule_ht, &event->ht_node);

	ret = kernctl_disable(event->fd);
	if (ret < 0) {
		PERROR("Failed to disable kernel event notifier: fd = %d, token = %" PRIu64,
		       event->fd,
		       event->token);
		goto error;
	}

	event->enabled = false;
	DBG("Disabled kernel event notifier: fd = %d, token = %" PRIu64, event->fd, event->token);

error:
	return ret;
}

/*
 * Make a kernel wait to make sure in-flight probe have completed.
 */
void kernel_wait_quiescent()
{
	int ret;
	const int fd = kernel_tracer_fd;

	DBG("Kernel quiescent wait on %d", fd);

	ret = kernctl_wait_quiescent(fd);
	if (ret < 0) {
		PERROR("wait quiescent ioctl");
		ERR("Kernel quiescent wait failed");
	}
}

/*
 * Get the event list from the kernel tracer and return the number of elements.
 */
ssize_t kernel_list_events(struct lttng_event **events)
{
	int fd, ret;
	char *event;
	size_t nbmem, count = 0;
	FILE *fp;
	struct lttng_event *elist;

	LTTNG_ASSERT(events);

	fd = kernctl_tracepoint_list(kernel_tracer_fd);
	if (fd < 0) {
		PERROR("kernel tracepoint list");
		goto error;
	}

	fp = fdopen(fd, "r");
	if (fp == nullptr) {
		PERROR("kernel tracepoint list fdopen");
		goto error_fp;
	}

	/*
	 * Init memory size counter
	 * See kernel-ctl.h for explanation of this value
	 */
	nbmem = KERNEL_EVENT_INIT_LIST_SIZE;
	elist = calloc<lttng_event>(nbmem);
	if (elist == nullptr) {
		PERROR("alloc list events");
		count = -ENOMEM;
		goto end;
	}

	while (fscanf(fp, "event { name = %m[^;]; };\n", &event) == 1) {
		if (count >= nbmem) {
			struct lttng_event *new_elist;
			size_t new_nbmem;

			new_nbmem = nbmem << 1;
			DBG("Reallocating event list from %zu to %zu bytes", nbmem, new_nbmem);
			new_elist = (lttng_event *) realloc(elist,
							    new_nbmem * sizeof(struct lttng_event));
			if (new_elist == nullptr) {
				PERROR("realloc list events");
				free(event);
				free(elist);
				count = -ENOMEM;
				goto end;
			}
			/* Zero the new memory */
			memset(new_elist + nbmem,
			       0,
			       (new_nbmem - nbmem) * sizeof(struct lttng_event));
			nbmem = new_nbmem;
			elist = new_elist;
		}
		strncpy(elist[count].name, event, LTTNG_SYMBOL_NAME_LEN);
		elist[count].name[LTTNG_SYMBOL_NAME_LEN - 1] = '\0';
		elist[count].enabled = -1;
		count++;
		free(event);
	}

	*events = elist;
	DBG("Kernel list events done (%zu events)", count);
end:
	ret = fclose(fp); /* closes both fp and fd */
	if (ret) {
		PERROR("fclose");
	}
	return count;

error_fp:
	ret = close(fd);
	if (ret) {
		PERROR("close");
	}
error:
	return -1;
}

/*
 * Get kernel version and validate it.
 */
int kernel_validate_version(struct lttng_kernel_abi_tracer_version *version,
			    struct lttng_kernel_abi_tracer_abi_version *abi_version)
{
	int ret;

	ret = kernctl_tracer_version(kernel_tracer_fd, version);
	if (ret < 0) {
		ERR("Failed to retrieve the lttng-modules version");
		goto error;
	}

	/* Validate version */
	if (version->major != VERSION_MAJOR) {
		ERR("Kernel tracer major version (%d) is not compatible with lttng-tools major version (%d)",
		    version->major,
		    VERSION_MAJOR);
		goto error_version;
	}
	ret = kernctl_tracer_abi_version(kernel_tracer_fd, abi_version);
	if (ret < 0) {
		ERR("Failed to retrieve lttng-modules ABI version");
		goto error;
	}
	if (abi_version->major != LTTNG_KERNEL_ABI_MAJOR_VERSION) {
		ERR("Kernel tracer ABI version (%d.%d) does not match the expected ABI major version (%d.*)",
		    abi_version->major,
		    abi_version->minor,
		    LTTNG_KERNEL_ABI_MAJOR_VERSION);
		goto error;
	}
	DBG2("Kernel tracer version validated (%d.%d, ABI %d.%d)",
	     version->major,
	     version->minor,
	     abi_version->major,
	     abi_version->minor);
	return 0;

error_version:
	ret = -1;

error:
	ERR("Kernel tracer version check failed; kernel tracing will not be available");
	return ret;
}

/*
 * Kernel work-arounds called at the start of sessiond main().
 */
int init_kernel_workarounds()
{
	int ret;
	FILE *fp;

	/*
	 * boot_id needs to be read once before being used concurrently
	 * to deal with a Linux kernel race. A fix is proposed for
	 * upstream, but the work-around is needed for older kernels.
	 */
	fp = fopen("/proc/sys/kernel/random/boot_id", "r");
	if (!fp) {
		goto end_boot_id;
	}
	while (!feof(fp)) {
		char buf[37] = "";

		ret = fread(buf, 1, sizeof(buf), fp);
		if (ret < 0) {
			/* Ignore error, we don't really care */
		}
	}
	ret = fclose(fp);
	if (ret) {
		PERROR("fclose");
	}
end_boot_id:
	return 0;
}

/*
 * Teardown of a kernel session, keeping data required by destroy notifiers.
 */
void kernel_destroy_session(struct ltt_kernel_session *ksess)
{
	if (ksess == nullptr) {
		DBG3("No kernel session when tearing down session");
		return;
	}

	DBG("Tearing down kernel session");

	/*
	 * Consumer stream group destruction (notifying the consumer to release
	 * its channel resources) is handled by the domain orchestrator's
	 * destructor, which runs after this function.
	 */

	/* Close any relayd session */
	consumer_output_send_destroy_relayd(ksess->consumer);

	trace_kernel_destroy_session(ksess);
}

/* Teardown of data required by destroy notifiers. */
void kernel_free_session(struct ltt_kernel_session *ksess)
{
	if (ksess == nullptr) {
		return;
	}
	trace_kernel_free_session(ksess);
}

/*
 * Get the syscall mask array from the kernel tracer.
 *
 * Return 0 on success else a negative value. In both case, syscall_mask should
 * be freed.
 */
int kernel_syscall_mask(int chan_fd, char **syscall_mask, uint32_t *nr_bits)
{
	LTTNG_ASSERT(syscall_mask);
	LTTNG_ASSERT(nr_bits);

	return kernctl_syscall_mask(chan_fd, syscall_mask, nr_bits);
}

static int kernel_tracer_abi_greater_or_equal(unsigned int major, unsigned int minor)
{
	int ret;
	struct lttng_kernel_abi_tracer_abi_version abi;

	ret = kernctl_tracer_abi_version(kernel_tracer_fd, &abi);
	if (ret < 0) {
		ERR("Failed to retrieve lttng-modules ABI version");
		goto error;
	}

	ret = abi.major > major || (abi.major == major && abi.minor >= minor);
error:
	return ret;
}

/*
 * Check for the support of the RING_BUFFER_SNAPSHOT_SAMPLE_POSITIONS via abi
 * version number.
 *
 * Return 1 on success, 0 when feature is not supported, negative value in case
 * of errors.
 */
int kernel_supports_ring_buffer_snapshot_sample_positions()
{
	/*
	 * RING_BUFFER_SNAPSHOT_SAMPLE_POSITIONS was introduced in 2.3
	 */
	return kernel_tracer_abi_greater_or_equal(2, 3);
}

/*
 * Check for the support of the packet sequence number via abi version number.
 *
 * Return 1 on success, 0 when feature is not supported, negative value in case
 * of errors.
 */
int kernel_supports_ring_buffer_packet_sequence_number()
{
	/*
	 * Packet sequence number was introduced in LTTng 2.8,
	 * lttng-modules ABI 2.1.
	 */
	return kernel_tracer_abi_greater_or_equal(2, 1);
}

/*
 * Check for the support of event notifiers via abi version number.
 *
 * Return 1 on success, 0 when feature is not supported, negative value in case
 * of errors.
 */
int kernel_supports_event_notifiers()
{
	/*
	 * Event notifiers were introduced in LTTng 2.13, lttng-modules ABI 2.6.
	 */
	return kernel_tracer_abi_greater_or_equal(2, 6);
}

enum lttng_error_code kernel_create_channel_subdirectories(struct lttng_trace_chunk *trace_chunk)
{
	enum lttng_error_code ret = LTTNG_OK;
	enum lttng_trace_chunk_status chunk_status;

	const lttng::urcu::read_lock_guard read_lock;
	LTTNG_ASSERT(trace_chunk);

	/*
	 * Create the index subdirectory which will take care
	 * of implicitly creating the channel's path.
	 */
	chunk_status = lttng_trace_chunk_create_subdirectory(
		trace_chunk, DEFAULT_KERNEL_TRACE_DIR "/" DEFAULT_INDEX_DIR);
	if (chunk_status != LTTNG_TRACE_CHUNK_STATUS_OK) {
		ret = LTTNG_ERR_CREATE_DIR_FAIL;
		goto error;
	}
error:
	return ret;
}

/*
 * Get current kernel tracer status
 */
enum lttng_kernel_tracer_status get_kernel_tracer_status()
{
	if (!kernel_tracer_status) {
		return LTTNG_KERNEL_TRACER_STATUS_ERR_UNKNOWN;
	}

	return *kernel_tracer_status;
}

/*
 * Sets the kernel tracer status based on the positive errno code
 */
void set_kernel_tracer_status_from_modules_ret(int code)
{
	switch (code) {
	case ENOENT:
	{
		kernel_tracer_status = nonstd::optional<enum lttng_kernel_tracer_status>(
			LTTNG_KERNEL_TRACER_STATUS_ERR_MODULES_MISSING);
		break;
	}
	case ENOKEY:
	case EKEYEXPIRED:
	case EKEYREVOKED:
	case EKEYREJECTED:
	{
		kernel_tracer_status = nonstd::optional<enum lttng_kernel_tracer_status>(
			LTTNG_KERNEL_TRACER_STATUS_ERR_MODULES_SIGNATURE);
		break;
	}
	default:
	{
		kernel_tracer_status = nonstd::optional<enum lttng_kernel_tracer_status>(
			LTTNG_KERNEL_TRACER_STATUS_ERR_MODULES_UNKNOWN);
		break;
	}
	}
}

/*
 * Setup necessary data for kernel tracer action.
 */
int init_kernel_tracer()
{
	int ret;
	const bool is_root = !getuid();

	const auto log_status_on_exit = lttng::make_scope_exit([]() noexcept {
		DBG_FMT("Kernel tracer status set to `{}`",
			kernel_tracer_status_to_str(*kernel_tracer_status));
	});

	/* Modprobe lttng kernel modules */
	ret = modprobe_lttng_control();
	if (ret < 0) {
		set_kernel_tracer_status_from_modules_ret(-ret);
		goto error;
	}

	/* Open debugfs lttng */
	kernel_tracer_fd = open(module_proc_lttng, O_RDWR);
	if (kernel_tracer_fd < 0) {
		DBG("Failed to open %s", module_proc_lttng);
		kernel_tracer_status = nonstd::optional<enum lttng_kernel_tracer_status>(
			LTTNG_KERNEL_TRACER_STATUS_ERR_OPEN_PROC_LTTNG);
		goto error_open;
	}

	/* Validate kernel version */
	ret = kernel_validate_version(&the_kernel_tracer_version, &the_kernel_tracer_abi_version);
	if (ret < 0) {
		kernel_tracer_status = nonstd::optional<enum lttng_kernel_tracer_status>(
			LTTNG_KERNEL_TRACER_STATUS_ERR_VERSION_MISMATCH);
		goto error_version;
	}

	ret = modprobe_lttng_data();
	if (ret < 0) {
		set_kernel_tracer_status_from_modules_ret(-ret);
		goto error_modules;
	}

	ret = kernel_supports_ring_buffer_snapshot_sample_positions();
	if (ret < 0) {
		goto error_modules;
	}
	if (ret < 1) {
		WARN("Kernel tracer does not support buffer monitoring. "
		     "The monitoring timer of channels in the kernel domain "
		     "will be set to 0 (disabled).");
	}

	ret = kernel_supports_event_notifiers();
	if (ret < 0) {
		ERR("Failed to check for kernel tracer event notifier support");
		kernel_tracer_status = nonstd::optional<enum lttng_kernel_tracer_status>(
			LTTNG_KERNEL_TRACER_STATUS_ERR_NOTIFIER);
		goto error_modules;
	}
	ret = kernel_create_event_notifier_group(&kernel_tracer_event_notifier_group_fd);
	if (ret < 0) {
		/* This is not fatal. */
		WARN("Failed to create kernel event notifier group");
		kernel_tracer_event_notifier_group_fd = -1;
	} else {
		enum event_notifier_error_accounting_status error_accounting_status;
		enum lttng_error_code error_code_ret =
			kernel_create_event_notifier_group_notification_fd(
				&kernel_tracer_event_notifier_group_notification_fd);

		if (error_code_ret != LTTNG_OK) {
			kernel_tracer_status = nonstd::optional<enum lttng_kernel_tracer_status>(
				LTTNG_KERNEL_TRACER_STATUS_ERR_NOTIFIER);
			goto error_modules;
		}

		error_accounting_status = event_notifier_error_accounting_register_kernel(
			kernel_tracer_event_notifier_group_fd);
		if (error_accounting_status != EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_OK) {
			ERR("Failed to initialize event notifier error accounting for kernel tracer");
			error_code_ret = LTTNG_ERR_EVENT_NOTIFIER_ERROR_ACCOUNTING;
			kernel_tracer_status = nonstd::optional<enum lttng_kernel_tracer_status>(
				LTTNG_KERNEL_TRACER_STATUS_ERR_NOTIFIER);
			goto error_modules;
		}

		kernel_token_to_event_notifier_rule_ht = cds_lfht_new(
			DEFAULT_HT_SIZE, 1, 0, CDS_LFHT_AUTO_RESIZE | CDS_LFHT_ACCOUNTING, nullptr);
		if (!kernel_token_to_event_notifier_rule_ht) {
			kernel_tracer_status = nonstd::optional<enum lttng_kernel_tracer_status>(
				LTTNG_KERNEL_TRACER_STATUS_ERR_NOTIFIER);
			goto error_token_ht;
		}
	}

	DBG("Kernel tracer initialized: kernel tracer fd = %d, event notifier group fd = %d, event notifier group notification fd = %d",
	    kernel_tracer_fd,
	    kernel_tracer_event_notifier_group_fd,
	    kernel_tracer_event_notifier_group_notification_fd);

	ret = syscall_init_table(kernel_tracer_fd);
	if (ret < 0) {
		ERR("Unable to populate syscall table. Syscall tracing won't "
		    "work for this session daemon.");
	}

	kernel_tracer_status = nonstd::optional<enum lttng_kernel_tracer_status>(
		LTTNG_KERNEL_TRACER_STATUS_INITIALIZED);
	return 0;

error_version:
	modprobe_remove_lttng_control();
	ret = close(kernel_tracer_fd);
	if (ret) {
		PERROR("Failed to close kernel tracer file descriptor: fd = %d", kernel_tracer_fd);
	}

	kernel_tracer_fd = -1;
	return LTTNG_ERR_KERN_VERSION;

error_token_ht:
	ret = close(kernel_tracer_event_notifier_group_notification_fd);
	if (ret) {
		PERROR("Failed to close kernel tracer event notifier group notification file descriptor: fd = %d",
		       kernel_tracer_event_notifier_group_notification_fd);
	}

	kernel_tracer_event_notifier_group_notification_fd = -1;

error_modules:
	ret = close(kernel_tracer_event_notifier_group_fd);
	if (ret) {
		PERROR("Failed to close kernel tracer event notifier group file descriptor: fd = %d",
		       kernel_tracer_event_notifier_group_fd);
	}

	kernel_tracer_event_notifier_group_fd = -1;

	ret = close(kernel_tracer_fd);
	if (ret) {
		PERROR("Failed to close kernel tracer file descriptor: fd = %d", kernel_tracer_fd);
	}

	kernel_tracer_fd = -1;

error_open:
	modprobe_remove_lttng_control();

error:
	WARN("No kernel tracer available");
	kernel_tracer_fd = -1;
	if (!is_root) {
		kernel_tracer_status = nonstd::optional<enum lttng_kernel_tracer_status>(
			LTTNG_KERNEL_TRACER_STATUS_ERR_NEED_ROOT);
		return LTTNG_ERR_NEED_ROOT_SESSIOND;
	} else {
		return LTTNG_ERR_KERN_NA;
	}
}

void cleanup_kernel_tracer()
{
	DBG2("Closing kernel event notifier group notification file descriptor");
	if (kernel_tracer_event_notifier_group_notification_fd >= 0) {
		int ret;

		if (kernel_tracer_event_notifier_group_notification_fd_registered) {
			ret = notification_thread_command_remove_tracer_event_source(
				the_notification_thread_handle,
				kernel_tracer_event_notifier_group_notification_fd);
			if (ret != LTTNG_OK) {
				ERR("Failed to remove kernel event notifier notification from notification thread");
			} else {
				kernel_tracer_event_notifier_group_notification_fd_registered =
					false;
			}
		}

		ret = close(kernel_tracer_event_notifier_group_notification_fd);
		if (ret) {
			PERROR("Failed to close kernel event notifier group notification file descriptor: fd = %d",
			       kernel_tracer_event_notifier_group_notification_fd);
		}

		kernel_tracer_event_notifier_group_notification_fd = -1;
	}

	if (kernel_token_to_event_notifier_rule_ht) {
		const int ret = cds_lfht_destroy(kernel_token_to_event_notifier_rule_ht, nullptr);
		LTTNG_ASSERT(ret == 0);
	}

	DBG2("Closing kernel event notifier group file descriptor");
	if (kernel_tracer_event_notifier_group_fd >= 0) {
		const int ret = close(kernel_tracer_event_notifier_group_fd);

		if (ret) {
			PERROR("Failed to close kernel event notifier group file descriptor: fd = %d",
			       kernel_tracer_event_notifier_group_fd);
		}

		kernel_tracer_event_notifier_group_fd = -1;
	}

	DBG2("Closing kernel fd");
	if (kernel_tracer_fd >= 0) {
		const int ret = close(kernel_tracer_fd);

		if (ret) {
			PERROR("Failed to close kernel tracer file descriptor: fd = %d",
			       kernel_tracer_fd);
		}

		kernel_tracer_fd = -1;
	}

	kernel_tracer_status = nonstd::nullopt;
}

bool kernel_tracer_is_initialized()
{
	return kernel_tracer_fd >= 0;
}

enum lttng_error_code
kernel_create_event_notifier_group_notification_fd(int *event_notifier_group_notification_fd)
{
	int local_fd = -1, ret;
	enum lttng_error_code error_code_ret;

	LTTNG_ASSERT(event_notifier_group_notification_fd);

	ret = kernctl_create_event_notifier_group_notification_fd(
		kernel_tracer_event_notifier_group_fd);
	if (ret < 0) {
		PERROR("Failed to create kernel event notifier group notification file descriptor");
		error_code_ret = LTTNG_ERR_EVENT_NOTIFIER_GROUP_NOTIFICATION_FD;
		goto error;
	}

	local_fd = ret;

	/* Prevent fd duplication after execlp(). */
	ret = fcntl(local_fd, F_SETFD, FD_CLOEXEC);
	if (ret < 0) {
		PERROR("Failed to set FD_CLOEXEC on kernel event notifier group notification file descriptor: fd = %d",
		       local_fd);
		error_code_ret = LTTNG_ERR_EVENT_NOTIFIER_GROUP_NOTIFICATION_FD;
		goto error;
	}

	DBG("Created kernel notifier group notification file descriptor: fd = %d", local_fd);
	error_code_ret = LTTNG_OK;
	*event_notifier_group_notification_fd = local_fd;
	local_fd = -1;

error:
	if (local_fd >= 0) {
		ret = close(local_fd);
		if (ret) {
			PERROR("Failed to close kernel event notifier group notification file descriptor: fd = %d",
			       local_fd);
		}
	}

	return error_code_ret;
}

enum lttng_error_code
kernel_destroy_event_notifier_group_notification_fd(int event_notifier_group_notification_fd)
{
	const lttng_error_code ret_code = LTTNG_OK;

	DBG("Closing event notifier group notification file descriptor: fd = %d",
	    event_notifier_group_notification_fd);
	if (event_notifier_group_notification_fd >= 0) {
		const int ret = close(event_notifier_group_notification_fd);
		if (ret) {
			PERROR("Failed to close event notifier group notification file descriptor: fd = %d",
			       event_notifier_group_notification_fd);
		}
	}

	return ret_code;
}

static unsigned long hash_trigger(const struct lttng_trigger *trigger)
{
	const struct lttng_condition *condition = lttng_trigger_get_const_condition(trigger);

	return lttng_condition_hash(condition);
}

static int match_trigger(struct cds_lfht_node *node, const void *key)
{
	const struct ltt_kernel_event_notifier_rule *event_notifier_rule;
	const struct lttng_trigger *trigger = (lttng_trigger *) key;

	event_notifier_rule =
		caa_container_of(node, const struct ltt_kernel_event_notifier_rule, ht_node);

	return lttng_trigger_is_equal(trigger, event_notifier_rule->trigger);
}

static enum lttng_error_code kernel_create_event_notifier_rule(
	struct lttng_trigger *trigger, const struct lttng_credentials *creds, uint64_t token)
{
	int err, fd, ret = 0;
	enum lttng_error_code error_code_ret;
	enum lttng_condition_status condition_status;
	enum lttng_condition_type condition_type;
	enum lttng_event_rule_type event_rule_type;
	struct ltt_kernel_event_notifier_rule *event_notifier_rule;
	struct lttng_kernel_abi_event_notifier kernel_event_notifier = {};
	unsigned int capture_bytecode_count = 0, i;
	const struct lttng_condition *condition = nullptr;
	const struct lttng_event_rule *event_rule = nullptr;
	enum lttng_condition_status cond_status;

	LTTNG_ASSERT(trigger);

	condition = lttng_trigger_get_const_condition(trigger);
	LTTNG_ASSERT(condition);

	condition_type = lttng_condition_get_type(condition);
	LTTNG_ASSERT(condition_type == LTTNG_CONDITION_TYPE_EVENT_RULE_MATCHES);

	/* Does not acquire a reference. */
	condition_status = lttng_condition_event_rule_matches_get_rule(condition, &event_rule);
	LTTNG_ASSERT(condition_status == LTTNG_CONDITION_STATUS_OK);
	LTTNG_ASSERT(event_rule);

	event_rule_type = lttng_event_rule_get_type(event_rule);
	LTTNG_ASSERT(event_rule_type != LTTNG_EVENT_RULE_TYPE_UNKNOWN);

	error_code_ret = trace_kernel_create_event_notifier_rule(
		trigger,
		token,
		lttng_condition_event_rule_matches_get_error_counter_index(condition),
		&event_notifier_rule);
	if (error_code_ret != LTTNG_OK) {
		goto error;
	}

	error_code_ret = trace_kernel_init_event_notifier_from_event_rule(event_rule,
									  &kernel_event_notifier);
	if (error_code_ret != LTTNG_OK) {
		goto free_event;
	}

	kernel_event_notifier.event.token = event_notifier_rule->token;
	kernel_event_notifier.error_counter_idx =
		lttng_condition_event_rule_matches_get_error_counter_index(condition);

	fd = kernctl_create_event_notifier(kernel_tracer_event_notifier_group_fd,
					   &kernel_event_notifier);
	if (fd < 0) {
		switch (-fd) {
		case EEXIST:
			error_code_ret = LTTNG_ERR_KERN_EVENT_EXIST;
			break;
		case ENOSYS:
			WARN("Failed to create kernel event notifier: not notifier type not implemented");
			error_code_ret = LTTNG_ERR_KERN_EVENT_ENOSYS;
			break;
		case ENOENT:
			WARN("Failed to create kernel event notifier: not found: name = '%s'",
			     kernel_event_notifier.event.name);
			error_code_ret = LTTNG_ERR_KERN_ENABLE_FAIL;
			break;
		default:
			PERROR("Failed to create kernel event notifier: error code = %d, name = '%s'",
			       fd,
			       kernel_event_notifier.event.name);
			error_code_ret = LTTNG_ERR_KERN_ENABLE_FAIL;
		}
		goto free_event;
	}

	event_notifier_rule->fd = fd;
	/* Prevent fd duplication after execlp(). */
	err = fcntl(event_notifier_rule->fd, F_SETFD, FD_CLOEXEC);
	if (err < 0) {
		PERROR("Failed to set FD_CLOEXEC on kernel event notifier file descriptor: fd = %d",
		       fd);
		error_code_ret = LTTNG_ERR_FATAL;
		goto set_cloexec_error;
	}

	if (event_notifier_rule->filter) {
		err = kernctl_filter(event_notifier_rule->fd, event_notifier_rule->filter);
		if (err < 0) {
			switch (-err) {
			case ENOMEM:
				error_code_ret = LTTNG_ERR_FILTER_NOMEM;
				break;
			default:
				error_code_ret = LTTNG_ERR_FILTER_INVAL;
				break;
			}
			goto filter_error;
		}
	}

	if (lttng_event_rule_get_type(event_rule) == LTTNG_EVENT_RULE_TYPE_KERNEL_UPROBE) {
		ret = userspace_probe_event_rule_add_callsites(
			event_rule, creds, event_notifier_rule->fd);
		if (ret) {
			error_code_ret = LTTNG_ERR_KERN_ENABLE_FAIL;
			goto add_callsite_error;
		}
	}

	/* Set the capture bytecode if any. */
	cond_status = lttng_condition_event_rule_matches_get_capture_descriptor_count(
		condition, &capture_bytecode_count);
	LTTNG_ASSERT(cond_status == LTTNG_CONDITION_STATUS_OK);

	for (i = 0; i < capture_bytecode_count; i++) {
		const struct lttng_bytecode *capture_bytecode =
			lttng_condition_event_rule_matches_get_capture_bytecode_at_index(condition,
											 i);

		if (capture_bytecode == nullptr) {
			ERR("Unexpected NULL capture bytecode on condition");
			error_code_ret = LTTNG_ERR_KERN_ENABLE_FAIL;
			goto capture_error;
		}

		ret = kernctl_capture(event_notifier_rule->fd, capture_bytecode);
		if (ret < 0) {
			ERR("Failed to set capture bytecode on event notifier rule fd: fd = %d",
			    event_notifier_rule->fd);
			error_code_ret = LTTNG_ERR_KERN_ENABLE_FAIL;
			goto capture_error;
		}
	}

	err = kernctl_enable(event_notifier_rule->fd);
	if (err < 0) {
		switch (-err) {
		case EEXIST:
			error_code_ret = LTTNG_ERR_KERN_EVENT_EXIST;
			break;
		default:
			PERROR("enable kernel event notifier");
			error_code_ret = LTTNG_ERR_KERN_ENABLE_FAIL;
			break;
		}
		goto enable_error;
	}

	/* Add trigger to kernel token mapping in the hash table. */
	{
		const lttng::urcu::read_lock_guard read_lock;
		cds_lfht_add(kernel_token_to_event_notifier_rule_ht,
			     hash_trigger(trigger),
			     &event_notifier_rule->ht_node);
	}

	DBG("Created kernel event notifier: name = '%s', fd = %d",
	    kernel_event_notifier.event.name,
	    event_notifier_rule->fd);

	return LTTNG_OK;

capture_error:
add_callsite_error:
enable_error:
set_cloexec_error:
filter_error:
{
	const int close_ret = close(event_notifier_rule->fd);

	if (close_ret) {
		PERROR("Failed to close kernel event notifier file descriptor: fd = %d",
		       event_notifier_rule->fd);
	}
}
free_event:
	free(event_notifier_rule);
error:
	return error_code_ret;
}

enum lttng_error_code kernel_register_event_notifier(struct lttng_trigger *trigger,
						     const struct lttng_credentials *cmd_creds)
{
	enum lttng_error_code ret;
	enum lttng_condition_status status;
	enum lttng_domain_type domain_type;
	const struct lttng_event_rule *event_rule;
	const struct lttng_condition *const condition = lttng_trigger_get_const_condition(trigger);
	const uint64_t token = lttng_trigger_get_tracer_token(trigger);

	LTTNG_ASSERT(condition);

	/* Does not acquire a reference to the event rule. */
	status = lttng_condition_event_rule_matches_get_rule(condition, &event_rule);
	LTTNG_ASSERT(status == LTTNG_CONDITION_STATUS_OK);

	domain_type = lttng_event_rule_get_domain_type(event_rule);
	LTTNG_ASSERT(domain_type == LTTNG_DOMAIN_KERNEL);

	ret = kernel_create_event_notifier_rule(trigger, cmd_creds, token);
	if (ret != LTTNG_OK) {
		ERR("Failed to create kernel event notifier rule");
	}

	return ret;
}

enum lttng_error_code kernel_unregister_event_notifier(const struct lttng_trigger *trigger)
{
	struct ltt_kernel_event_notifier_rule *token_event_rule_element;
	struct cds_lfht_node *node;
	struct cds_lfht_iter iter;
	enum lttng_error_code error_code_ret;
	int ret;

	const lttng::urcu::read_lock_guard read_lock;

	cds_lfht_lookup(kernel_token_to_event_notifier_rule_ht,
			hash_trigger(trigger),
			match_trigger,
			trigger,
			&iter);

	node = cds_lfht_iter_get_node(&iter);
	if (!node) {
		error_code_ret = LTTNG_ERR_TRIGGER_NOT_FOUND;
		goto error;
	}

	token_event_rule_element =
		caa_container_of(node, struct ltt_kernel_event_notifier_rule, ht_node);

	ret = kernel_disable_event_notifier_rule(token_event_rule_element);
	if (ret) {
		error_code_ret = LTTNG_ERR_FATAL;
		goto error;
	}

	trace_kernel_destroy_event_notifier_rule(token_event_rule_element);
	error_code_ret = LTTNG_OK;

error:

	return error_code_ret;
}

int kernel_get_notification_fd()
{
	return kernel_tracer_event_notifier_group_notification_fd;
}

void kernel_set_notification_fd_registered()
{
	kernel_tracer_event_notifier_group_notification_fd_registered = true;
}
