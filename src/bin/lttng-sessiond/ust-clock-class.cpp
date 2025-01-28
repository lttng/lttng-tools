/*
 * SPDX-FileCopyrightText: 2010 Pierre-Marc Fournier
 * SPDX-FileCopyrightText: 2011 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 * SPDX-FileCopyrightText: 2022 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include "ust-clock-class.hpp"

#include <common/exception.hpp>
#include <common/time.hpp>

#include <lttng/ust-clock.h>

#define CLOCK_OFFSET_SAMPLE_COUNT 10

namespace lst = lttng::sessiond::trace;

namespace {
struct offset_sample {
	/* correlation offset */
	lst::clock_class::scycles_t offset;
	/* lower is better */
	lst::clock_class::cycles_t measure_delta;
};

lst::clock_class::cycles_t sample_clock_read64()
{
	lttng_ust_clock_read64_function read64_cb;

	if (lttng_ust_trace_clock_get_read64_cb(&read64_cb)) {
		LTTNG_THROW_ERROR("Failed to get clock sample callback");
	}

	return read64_cb();
}

lst::clock_class::cycles_t sample_clock_frequency()
{
	lttng_ust_clock_freq_function get_freq_cb;

	if (lttng_ust_trace_clock_get_freq_cb(&get_freq_cb)) {
		LTTNG_THROW_ERROR("Failed to get clock frequency callback");
	}

	return get_freq_cb();
}

nonstd::optional<lttng_uuid> sample_clock_uuid()
{
	lttng_ust_clock_uuid_function get_uuid_cb;

	if (lttng_ust_trace_clock_get_uuid_cb(&get_uuid_cb)) {
		return nonstd::nullopt;
	}

	char uuid_str[LTTNG_UUID_STR_LEN];
	if (get_uuid_cb(uuid_str)) {
		return nonstd::nullopt;
	}

	lttng_uuid uuid;
	if (lttng_uuid_from_str(uuid_str, uuid)) {
		LTTNG_THROW_ERROR("Failed to parse UUID from string");
	}

	return nonstd::optional<lttng_uuid>{ uuid };
}

const char *sample_clock_name()
{
	lttng_ust_clock_name_function get_name_cb;

	if (lttng_ust_trace_clock_get_name_cb(&get_name_cb)) {
		LTTNG_THROW_ERROR("Failed to get clock name callback");
	}

	const auto name = get_name_cb();
	if (!name) {
		LTTNG_THROW_ERROR(
			"Invalid clock name returned by LTTng-UST `lttng_ust_clock_name_function`");
	}

	return name;
}

const char *sample_clock_description()
{
	lttng_ust_clock_description_function get_description_cb;

	if (lttng_ust_trace_clock_get_description_cb(&get_description_cb)) {
		LTTNG_THROW_ERROR("Failed to get clock description callback");
	}

	const auto description = get_description_cb();
	if (!description) {
		LTTNG_THROW_ERROR(
			"Invalid clock description returned by LTTng-UST `lttng_ust_clock_description_function`");
	}

	return description;
}

/*
 * The offset between monotonic and realtime clock can be negative if
 * the system sets the REALTIME clock to 0 after boot.
 */
void measure_single_clock_offset(struct offset_sample *sample)
{
	lst::clock_class::cycles_t monotonic_avg, monotonic[2], measure_delta, realtime;
	const auto tcf = sample_clock_frequency();
	struct timespec rts = { 0, 0 };

	monotonic[0] = sample_clock_read64();
	if (lttng_clock_gettime(CLOCK_REALTIME, &rts)) {
		LTTNG_THROW_POSIX("Failed to sample time from clock", errno);
	}

	monotonic[1] = sample_clock_read64();
	measure_delta = monotonic[1] - monotonic[0];
	if (measure_delta > sample->measure_delta) {
		/*
		 * Discard value if it took longer to read than the best
		 * sample so far.
		 */
		return;
	}

	monotonic_avg = (monotonic[0] + monotonic[1]) >> 1;
	realtime = (lst::clock_class::cycles_t) rts.tv_sec * tcf;
	if (tcf == NSEC_PER_SEC) {
		realtime += rts.tv_nsec;
	} else {
		realtime += (lst::clock_class::cycles_t) rts.tv_nsec * tcf / NSEC_PER_SEC;
	}

	sample->offset = (lst::clock_class::scycles_t) realtime - monotonic_avg;
	sample->measure_delta = measure_delta;
}

/*
 * Approximation of NTP time of day to clock monotonic correlation,
 * taken at start of trace. Keep the measurement that took the less time
 * to complete, thus removing imprecision caused by preemption.
 * May return a negative offset.
 */
lst::clock_class::scycles_t measure_clock_offset()
{
	struct offset_sample offset_best_sample = {
		.offset = 0,
		.measure_delta = UINT64_MAX,
	};

	for (auto i = 0; i < CLOCK_OFFSET_SAMPLE_COUNT; i++) {
		measure_single_clock_offset(&offset_best_sample);
	}

	return offset_best_sample.offset;
}
} /* namespace */

lttng::sessiond::ust::clock_class::clock_class() :
	lst::clock_class(sample_clock_name(),
			 sample_clock_description(),
			 sample_clock_uuid(),
			 measure_clock_offset(),
			 sample_clock_frequency())
{
}
