/*
 * SPDX-FileCopyrightText: 2011 EfficiOS Inc.
 * SPDX-FileCopyrightText: 2011 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef _LTTNG_USTCONSUMER_H
#define _LTTNG_USTCONSUMER_H

#include <common/compat/errno.hpp>
#include <common/consumer/consumer.hpp>
#include <common/consumer/reclaim.hpp>
#include <common/exception.hpp>

#include <set>
#include <stdbool.h>

#ifdef HAVE_LIBLTTNG_UST_CTL

int lttng_ustconsumer_take_snapshot(struct lttng_consumer_stream *stream);
int lttng_ustconsumer_sample_snapshot_positions(struct lttng_consumer_stream *stream) noexcept;

int lttng_ustconsumer_get_produced_snapshot(struct lttng_consumer_stream *stream,
					    unsigned long *pos) noexcept;
int lttng_ustconsumer_get_consumed_snapshot(struct lttng_consumer_stream *stream,
					    unsigned long *pos) noexcept;

int lttng_ustconsumer_recv_cmd(struct lttng_consumer_local_data *ctx,
			       int sock,
			       struct pollfd *consumer_sockpoll);

extern void lttng_ustconsumer_del_channel(struct lttng_consumer_channel *chan);
extern void lttng_ustconsumer_free_channel(struct lttng_consumer_channel *chan);
extern int lttng_ustconsumer_add_stream(struct lttng_consumer_stream *stream);
extern void lttng_ustconsumer_del_stream(struct lttng_consumer_stream *stream);

int lttng_ustconsumer_read_subbuffer(struct lttng_consumer_stream *stream,
				     struct lttng_consumer_local_data *ctx);
int lttng_ustconsumer_on_recv_stream(struct lttng_consumer_stream *stream);

void lttng_ustconsumer_on_stream_hangup(struct lttng_consumer_stream *stream);

int lttng_ustconsumer_get_stream_id(struct lttng_consumer_stream *stream, uint64_t *stream_id);
int lttng_ustconsumer_data_pending(struct lttng_consumer_stream *stream);
void lttng_ustconsumer_close_all_metadata(struct lttng_ht *ht);
void lttng_ustconsumer_close_metadata(struct lttng_consumer_channel *metadata);
void lttng_ustconsumer_close_stream_wakeup(struct lttng_consumer_stream *stream);
int lttng_ustconsumer_recv_metadata(int sock,
				    uint64_t key,
				    uint64_t offset,
				    uint64_t len,
				    uint64_t version,
				    struct lttng_consumer_channel *channel,
				    bool invoked_by_timer,
				    int wait);
int lttng_ustconsumer_request_metadata(lttng_consumer_channel& channel,
				       protected_socket& sessiond_metadata_socket,
				       protected_socket& consumer_error_socket,
				       bool invoked_by_timer,
				       int wait);
enum sync_metadata_status lttng_ustconsumer_sync_metadata(struct lttng_consumer_local_data *ctx,
							  struct lttng_consumer_stream *metadata);
int lttng_ustconsumer_flush_buffer(struct lttng_consumer_stream *stream, int producer);
int lttng_ustconsumer_flush_buffer_or_populate_packet(
	struct lttng_consumer_stream *stream,
	struct lttng_ust_ctl_consumer_packet *terminal_packet,
	bool *packet_populated,
	bool *flush_done);
int lttng_ustconsumer_clear_buffer(struct lttng_consumer_stream *stream);
int lttng_ustconsumer_get_current_timestamp(struct lttng_consumer_stream *stream, uint64_t *ts);
int lttng_ustconsumer_get_sequence_number(struct lttng_consumer_stream *stream, uint64_t *seq);
void lttng_ustconsumer_sigbus_handle(void *addr);

uint32_t lttng_ustconsumer_reclaim_session_owner_id(uint64_t session_id, uint32_t owner_id);

int lttng_ustconsumer_fixup_stalled_channel(struct lttng_consumer_channel *channel,
					    std::set<uint32_t>& reclaimed_owner_ids,
					    size_t& observed_count);

void lttng_ustconsumer_quiescent_stalled_channel(struct lttng_consumer_local_data& ctx,
						 struct lttng_consumer_channel& channel);

void lttng_ustconsumer_try_reclaim_current_subbuffer(lttng_consumer_stream& stream,
						     const stream_subbuffer& subbuffer);

lttng::consumer::memory_reclaim_result lttng_ustconsumer_reclaim_stream_memory(
	lttng_consumer_stream& stream,
	std::optional<std::chrono::microseconds> age_limit,
	bool require_consumed,
	const std::optional<std::uint64_t>& memory_reclaim_request_token);

#else /* HAVE_LIBLTTNG_UST_CTL */

static inline ssize_t
lttng_ustconsumer_on_read_subbuffer_mmap([[maybe_unused]] struct lttng_consumer_local_data *ctx,
					 [[maybe_unused]] struct lttng_consumer_stream *stream,
					 [[maybe_unused]] unsigned long len,
					 [[maybe_unused]] unsigned long padding)
{
	return -ENOSYS;
}

static inline ssize_t
lttng_ustconsumer_on_read_subbuffer_splice([[maybe_unused]] struct lttng_consumer_local_data *ctx,
					   [[maybe_unused]] struct lttng_consumer_stream *uststream,
					   [[maybe_unused]] unsigned long len,
					   [[maybe_unused]] unsigned long padding)
{
	return -ENOSYS;
}

static inline int
lttng_ustconsumer_take_snapshot([[maybe_unused]] struct lttng_consumer_stream *stream)
{
	return -ENOSYS;
}

static inline int lttng_ustconsumer_sample_snapshot_positions(
	[[maybe_unused]] struct lttng_consumer_stream *stream) noexcept
{
	return -ENOSYS;
}

static inline int
lttng_ustconsumer_get_produced_snapshot([[maybe_unused]] struct lttng_consumer_stream *stream,
					[[maybe_unused]] unsigned long *pos) noexcept
{
	return -ENOSYS;
}

static inline int
lttng_ustconsumer_get_consumed_snapshot([[maybe_unused]] struct lttng_consumer_stream *stream,
					[[maybe_unused]] unsigned long *pos) noexcept
{
	return -ENOSYS;
}

static inline int lttng_ustconsumer_recv_cmd([[maybe_unused]] struct lttng_consumer_local_data *ctx,
					     [[maybe_unused]] int sock,
					     [[maybe_unused]] struct pollfd *consumer_sockpoll)
{
	return -ENOSYS;
}

static inline void
lttng_ustconsumer_del_channel([[maybe_unused]] struct lttng_consumer_channel *chan)
{
}

static inline void
lttng_ustconsumer_free_channel([[maybe_unused]] struct lttng_consumer_channel *chan)
{
}

static inline int
lttng_ustconsumer_add_stream([[maybe_unused]] struct lttng_consumer_stream *stream)
{
	return -ENOSYS;
}

static inline void
lttng_ustconsumer_del_stream([[maybe_unused]] struct lttng_consumer_stream *stream)
{
}

static inline int
lttng_ustconsumer_read_subbuffer([[maybe_unused]] struct lttng_consumer_stream *stream,
				 [[maybe_unused]] struct lttng_consumer_local_data *ctx)
{
	return -ENOSYS;
}

static inline int
lttng_ustconsumer_on_recv_stream([[maybe_unused]] struct lttng_consumer_stream *stream)
{
	return -ENOSYS;
}

static inline void
lttng_ustconsumer_on_stream_hangup([[maybe_unused]] struct lttng_consumer_stream *stream)
{
}

static inline int
lttng_ustconsumer_data_pending([[maybe_unused]] struct lttng_consumer_stream *stream)
{
	return -ENOSYS;
}

static inline void lttng_ustconsumer_close_all_metadata([[maybe_unused]] struct lttng_ht *ht)
{
}

static inline void
lttng_ustconsumer_close_metadata([[maybe_unused]] struct lttng_consumer_channel *metadata)
{
}
static inline void
lttng_ustconsumer_close_stream_wakeup([[maybe_unused]] struct lttng_consumer_stream *stream)
{
}

static inline int
lttng_ustconsumer_recv_metadata([[maybe_unused]] int sock,
				[[maybe_unused]] uint64_t key,
				[[maybe_unused]] uint64_t offset,
				[[maybe_unused]] uint64_t len,
				[[maybe_unused]] uint64_t version,
				[[maybe_unused]] struct lttng_consumer_channel *channel,
				[[maybe_unused]] bool invoked_by_timer)
{
	return -ENOSYS;
}

static inline int
lttng_ustconsumer_request_metadata([[maybe_unused]] lttng_consumer_channel& channel,
				   [[maybe_unused]] protected_socket& sessiond_metadata_socket,
				   [[maybe_unused]] protected_socket& consumer_error_socket,
				   [[maybe_unused]] bool invoked_by_timer,
				   [[maybe_unused]] int wait)
{
	return -ENOSYS;
}

static inline enum sync_metadata_status
lttng_ustconsumer_sync_metadata([[maybe_unused]] struct lttng_consumer_local_data *ctx,
				[[maybe_unused]] struct lttng_consumer_stream *metadata)
{
	return SYNC_METADATA_STATUS_ERROR;
}

static inline int
lttng_ustconsumer_flush_buffer([[maybe_unused]] struct lttng_consumer_stream *stream,
			       [[maybe_unused]] int producer)
{
	return -ENOSYS;
}

static inline int lttng_ustconsumer_flush_buffer_with_old_position(
	[[maybe_unused]] struct lttng_consumer_stream *stream,
	[[maybe_unused]] int producer,
	[[maybe_unused]] unsigned long *old_position)
{
	return -ENOSYS;
}

static inline int
lttng_ustconsumer_clear_buffer([[maybe_unused]] struct lttng_consumer_stream *stream)
{
	return -ENOSYS;
}

static inline int
lttng_ustconsumer_get_current_timestamp([[maybe_unused]] struct lttng_consumer_stream *stream,
					[[maybe_unused]] uint64_t *ts)
{
	return -ENOSYS;
}

static inline int
lttng_ustconsumer_get_sequence_number([[maybe_unused]] struct lttng_consumer_stream *stream,
				      [[maybe_unused]] uint64_t *seq)
{
	return -ENOSYS;
}

static inline int
lttng_ustconsumer_get_stream_id([[maybe_unused]] struct lttng_consumer_stream *stream,
				[[maybe_unused]] uint64_t *stream_id)
{
	return -ENOSYS;
}

static inline void lttng_ustconsumer_sigbus_handle([[maybe_unused]] void *addr)
{
}
static inline uint32_t
lttng_ustconsumer_reclaim_session_owner_id([[maybe_unused]] uint64_t session_id,
					   [[maybe_unused]] uint32_t owner_id)
{
	return 0;
}

static inline int
lttng_ustconsumer_fixup_stalled_channel([[maybe_unused]] struct lttng_consumer_channel *channel,
					[[maybe_unused]] std::set<uint32_t>& reclaimed_owner_ids,
					[[maybe_unused]] size_t& observed_count)
{
	return -ENOSYS;
}

static inline void
lttng_ustconsumer_quiescent_stalled_channel([[maybe_unused]] struct lttng_consumer_local_data& ctx,
					    [[maybe_unused]] struct lttng_consumer_channel& channel)
{
}

static inline void lttng_ustconsumer_try_reclaim_current_subbuffer(lttng_consumer_stream& stream
								   [[maybe_unused]],
								   const stream_subbuffer& subbuffer
								   [[maybe_unused]])
{
}

static inline lttng::consumer::memory_reclaim_result lttng_ustconsumer_reclaim_stream_memory(
	lttng_consumer_stream& stream [[maybe_unused]],
	std::optional<std::chrono::microseconds> age_limit [[maybe_unused]],
	bool require_consumed [[maybe_unused]],
	const std::optional<std::uint64_t>& memory_reclaim_request_token [[maybe_unused]])
{
	std::abort();
	return {};
}

#endif /* HAVE_LIBLTTNG_UST_CTL */

#endif /* _LTTNG_USTCONSUMER_H */
