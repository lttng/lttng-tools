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
	nonstd::optional<std::chrono::microseconds> age_limit,
	bool require_consumed,
	const nonstd::optional<std::uint64_t>& memory_reclaim_request_token);

#else /* HAVE_LIBLTTNG_UST_CTL */

static inline ssize_t lttng_ustconsumer_on_read_subbuffer_mmap(
	struct lttng_consumer_local_data *ctx __attribute__((unused)),
	struct lttng_consumer_stream *stream __attribute__((unused)),
	unsigned long len __attribute__((unused)),
	unsigned long padding __attribute__((unused)))
{
	return -ENOSYS;
}

static inline ssize_t lttng_ustconsumer_on_read_subbuffer_splice(
	struct lttng_consumer_local_data *ctx __attribute__((unused)),
	struct lttng_consumer_stream *uststream __attribute__((unused)),
	unsigned long len __attribute__((unused)),
	unsigned long padding __attribute__((unused)))
{
	return -ENOSYS;
}

static inline int lttng_ustconsumer_take_snapshot(struct lttng_consumer_stream *stream
						  __attribute__((unused)))
{
	return -ENOSYS;
}

static inline int lttng_ustconsumer_sample_snapshot_positions(struct lttng_consumer_stream *stream
							      __attribute__((unused))) noexcept
{
	return -ENOSYS;
}

static inline int lttng_ustconsumer_get_produced_snapshot(struct lttng_consumer_stream *stream
							  __attribute__((unused)),
							  unsigned long *pos
							  __attribute__((unused))) noexcept
{
	return -ENOSYS;
}

static inline int lttng_ustconsumer_get_consumed_snapshot(struct lttng_consumer_stream *stream
							  __attribute__((unused)),
							  unsigned long *pos
							  __attribute__((unused))) noexcept
{
	return -ENOSYS;
}

static inline int lttng_ustconsumer_recv_cmd(struct lttng_consumer_local_data *ctx
					     __attribute__((unused)),
					     int sock __attribute__((unused)),
					     struct pollfd *consumer_sockpoll
					     __attribute__((unused)))
{
	return -ENOSYS;
}

static inline void lttng_ustconsumer_del_channel(struct lttng_consumer_channel *chan
						 __attribute__((unused)))
{
}

static inline void lttng_ustconsumer_free_channel(struct lttng_consumer_channel *chan
						  __attribute__((unused)))
{
}

static inline int lttng_ustconsumer_add_stream(struct lttng_consumer_stream *stream
					       __attribute__((unused)))
{
	return -ENOSYS;
}

static inline void lttng_ustconsumer_del_stream(struct lttng_consumer_stream *stream
						__attribute__((unused)))
{
}

static inline int lttng_ustconsumer_read_subbuffer(struct lttng_consumer_stream *stream
						   __attribute__((unused)),
						   struct lttng_consumer_local_data *ctx
						   __attribute__((unused)))
{
	return -ENOSYS;
}

static inline int lttng_ustconsumer_on_recv_stream(struct lttng_consumer_stream *stream
						   __attribute__((unused)))
{
	return -ENOSYS;
}

static inline void lttng_ustconsumer_on_stream_hangup(struct lttng_consumer_stream *stream
						      __attribute__((unused)))
{
}

static inline int lttng_ustconsumer_data_pending(struct lttng_consumer_stream *stream
						 __attribute__((unused)))
{
	return -ENOSYS;
}

static inline void lttng_ustconsumer_close_all_metadata(struct lttng_ht *ht __attribute__((unused)))
{
}

static inline void lttng_ustconsumer_close_metadata(struct lttng_consumer_channel *metadata
						    __attribute__((unused)))
{
}
static inline void lttng_ustconsumer_close_stream_wakeup(struct lttng_consumer_stream *stream
							 __attribute__((unused)))
{
}

static inline int lttng_ustconsumer_recv_metadata(int sock __attribute__((unused)),
						  uint64_t key __attribute__((unused)),
						  uint64_t offset __attribute__((unused)),
						  uint64_t len __attribute__((unused)),
						  uint64_t version __attribute__((unused)),
						  struct lttng_consumer_channel *channel
						  __attribute__((unused)),
						  bool invoked_by_timer __attribute__((unused)))
{
	return -ENOSYS;
}

static inline int lttng_ustconsumer_request_metadata(lttng_consumer_channel& channel
						     __attribute__((unused)),
						     protected_socket& sessiond_metadata_socket
						     __attribute__((unused)),
						     protected_socket& consumer_error_socket
						     __attribute__((unused)),
						     bool invoked_by_timer __attribute__((unused)),
						     int wait __attribute__((unused)))
{
	return -ENOSYS;
}

static inline enum sync_metadata_status
lttng_ustconsumer_sync_metadata(struct lttng_consumer_local_data *ctx __attribute__((unused)),
				struct lttng_consumer_stream *metadata __attribute__((unused)))
{
	return SYNC_METADATA_STATUS_ERROR;
}

static inline int lttng_ustconsumer_flush_buffer(struct lttng_consumer_stream *stream
						 __attribute__((unused)),
						 int producer __attribute__((unused)))
{
	return -ENOSYS;
}

static inline int lttng_ustconsumer_flush_buffer_with_old_position(
	struct lttng_consumer_stream *stream __attribute__((unused)),
	int producer __attribute__((unused)),
	unsigned long *old_position __attribute__((unused)))
{
	return -ENOSYS;
}

static inline int lttng_ustconsumer_clear_buffer(struct lttng_consumer_stream *stream
						 __attribute__((unused)))
{
	return -ENOSYS;
}

static inline int lttng_ustconsumer_get_current_timestamp(struct lttng_consumer_stream *stream
							  __attribute__((unused)),
							  uint64_t *ts __attribute__((unused)))
{
	return -ENOSYS;
}

static inline int lttng_ustconsumer_get_sequence_number(struct lttng_consumer_stream *stream
							__attribute__((unused)),
							uint64_t *seq __attribute__((unused)))
{
	return -ENOSYS;
}

static inline int lttng_ustconsumer_get_stream_id(struct lttng_consumer_stream *stream
						  __attribute__((unused)),
						  uint64_t *stream_id __attribute__((unused)))
{
	return -ENOSYS;
}

static inline void lttng_ustconsumer_sigbus_handle(void *addr __attribute__((unused)))
{
}
static inline uint32_t lttng_ustconsumer_reclaim_session_owner_id(uint64_t session_id
								  __attribute__((unused)),
								  uint32_t owner_id
								  __attribute__((unused)))
{
	return 0;
}

static inline int lttng_ustconsumer_fixup_stalled_channel(struct lttng_consumer_channel *channel
							  __attribute__((unused)),
							  std::set<uint32_t>& reclaimed_owner_ids
							  __attribute__((unused)),
							  size_t& observed_count
							  __attribute__((unused)))
{
	return -ENOSYS;
}

static inline void
lttng_ustconsumer_quiescent_stalled_channel(struct lttng_consumer_local_data& ctx
					    __attribute__((unused)),
					    struct lttng_consumer_channel& channel
					    __attribute__((unused)))
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
	nonstd::optional<std::chrono::microseconds> age_limit [[maybe_unused]],
	bool require_consumed [[maybe_unused]],
	const nonstd::optional<std::uint64_t>& memory_reclaim_request_token [[maybe_unused]])
{
	std::abort();
	return {};
}

#endif /* HAVE_LIBLTTNG_UST_CTL */

#endif /* _LTTNG_USTCONSUMER_H */
