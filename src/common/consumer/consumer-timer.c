/*
 * Copyright (C) 2012 - Julien Desfossez <julien.desfossez@efficios.com>
 *                      David Goulet <dgoulet@efficios.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License, version 2 only, as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#define _LGPL_SOURCE
#include <assert.h>
#include <inttypes.h>
#include <signal.h>

#include <bin/lttng-sessiond/ust-ctl.h>
#include <bin/lttng-consumerd/health-consumerd.h>
#include <common/common.h>
#include <common/compat/endian.h>
#include <common/kernel-ctl/kernel-ctl.h>
#include <common/kernel-consumer/kernel-consumer.h>
#include <common/consumer/consumer-stream.h>
#include <common/consumer/consumer-timer.h>
#include <common/consumer/consumer-testpoint.h>
#include <common/ust-consumer/ust-consumer.h>

typedef int (*sample_positions_cb)(struct lttng_consumer_stream *stream);
typedef int (*get_consumed_cb)(struct lttng_consumer_stream *stream,
		unsigned long *consumed);
typedef int (*get_produced_cb)(struct lttng_consumer_stream *stream,
		unsigned long *produced);

static struct timer_signal_data timer_signal = {
	.tid = 0,
	.setup_done = 0,
	.qs_done = 0,
	.lock = PTHREAD_MUTEX_INITIALIZER,
};

/*
 * Set custom signal mask to current thread.
 */
static void setmask(sigset_t *mask)
{
	int ret;

	ret = sigemptyset(mask);
	if (ret) {
		PERROR("sigemptyset");
	}
	ret = sigaddset(mask, LTTNG_CONSUMER_SIG_SWITCH);
	if (ret) {
		PERROR("sigaddset switch");
	}
	ret = sigaddset(mask, LTTNG_CONSUMER_SIG_TEARDOWN);
	if (ret) {
		PERROR("sigaddset teardown");
	}
	ret = sigaddset(mask, LTTNG_CONSUMER_SIG_LIVE);
	if (ret) {
		PERROR("sigaddset live");
	}
	ret = sigaddset(mask, LTTNG_CONSUMER_SIG_MONITOR);
	if (ret) {
		PERROR("sigaddset monitor");
	}
	ret = sigaddset(mask, LTTNG_CONSUMER_SIG_EXIT);
	if (ret) {
		PERROR("sigaddset exit");
	}
}

static int channel_monitor_pipe = -1;

/*
 * Execute action on a timer switch.
 *
 * Beware: metadata_switch_timer() should *never* take a mutex also held
 * while consumer_timer_switch_stop() is called. It would result in
 * deadlocks.
 */
static void metadata_switch_timer(struct lttng_consumer_local_data *ctx,
		int sig, siginfo_t *si)
{
	int ret;
	struct lttng_consumer_channel *channel;

	channel = si->si_value.sival_ptr;
	assert(channel);

	if (channel->switch_timer_error) {
		return;
	}

	DBG("Switch timer for channel %" PRIu64, channel->key);
	switch (ctx->type) {
	case LTTNG_CONSUMER32_UST:
	case LTTNG_CONSUMER64_UST:
		/*
		 * Locks taken by lttng_ustconsumer_request_metadata():
		 * - metadata_socket_lock
		 *   - Calling lttng_ustconsumer_recv_metadata():
		 *     - channel->metadata_cache->lock
		 *     - Calling consumer_metadata_cache_flushed():
		 *       - channel->timer_lock
		 *         - channel->metadata_cache->lock
		 *
		 * Ensure that neither consumer_data.lock nor
		 * channel->lock are taken within this function, since
		 * they are held while consumer_timer_switch_stop() is
		 * called.
		 */
		ret = lttng_ustconsumer_request_metadata(ctx, channel, 1, 1);
		if (ret < 0) {
			channel->switch_timer_error = 1;
		}
		break;
	case LTTNG_CONSUMER_KERNEL:
	case LTTNG_CONSUMER_UNKNOWN:
		assert(0);
		break;
	}
}

static int send_empty_index(struct lttng_consumer_stream *stream, uint64_t ts,
		uint64_t stream_id)
{
	int ret;
	struct ctf_packet_index index;

	memset(&index, 0, sizeof(index));
	index.stream_id = htobe64(stream_id);
	index.timestamp_end = htobe64(ts);
	ret = consumer_stream_write_index(stream, &index);
	if (ret < 0) {
		goto error;
	}

error:
	return ret;
}

int consumer_flush_kernel_index(struct lttng_consumer_stream *stream)
{
	uint64_t ts, stream_id;
	int ret;

	ret = kernctl_get_current_timestamp(stream->wait_fd, &ts);
	if (ret < 0) {
		ERR("Failed to get the current timestamp");
		goto end;
	}
	ret = kernctl_buffer_flush(stream->wait_fd);
	if (ret < 0) {
		ERR("Failed to flush kernel stream");
		goto end;
	}
	ret = kernctl_snapshot(stream->wait_fd);
	if (ret < 0) {
		if (ret != -EAGAIN && ret != -ENODATA) {
			PERROR("live timer kernel snapshot");
			ret = -1;
			goto end;
		}
		ret = kernctl_get_stream_id(stream->wait_fd, &stream_id);
		if (ret < 0) {
			PERROR("kernctl_get_stream_id");
			goto end;
		}
		DBG("Stream %" PRIu64 " empty, sending beacon", stream->key);
		ret = send_empty_index(stream, ts, stream_id);
		if (ret < 0) {
			goto end;
		}
	}
	ret = 0;
end:
	return ret;
}

static int check_kernel_stream(struct lttng_consumer_stream *stream)
{
	int ret;

	/*
	 * While holding the stream mutex, try to take a snapshot, if it
	 * succeeds, it means that data is ready to be sent, just let the data
	 * thread handle that. Otherwise, if the snapshot returns EAGAIN, it
	 * means that there is no data to read after the flush, so we can
	 * safely send the empty index.
	 *
	 * Doing a trylock and checking if waiting on metadata if
	 * trylock fails. Bail out of the stream is indeed waiting for
	 * metadata to be pushed. Busy wait on trylock otherwise.
	 */
	for (;;) {
		ret = pthread_mutex_trylock(&stream->lock);
		switch (ret) {
		case 0:
			break;	/* We have the lock. */
		case EBUSY:
			pthread_mutex_lock(&stream->metadata_timer_lock);
			if (stream->waiting_on_metadata) {
				ret = 0;
				stream->missed_metadata_flush = true;
				pthread_mutex_unlock(&stream->metadata_timer_lock);
				goto end;	/* Bail out. */
			}
			pthread_mutex_unlock(&stream->metadata_timer_lock);
			/* Try again. */
			caa_cpu_relax();
			continue;
		default:
			ERR("Unexpected pthread_mutex_trylock error %d", ret);
			ret = -1;
			goto end;
		}
		break;
	}
	ret = consumer_flush_kernel_index(stream);
	pthread_mutex_unlock(&stream->lock);
end:
	return ret;
}

int consumer_flush_ust_index(struct lttng_consumer_stream *stream)
{
	uint64_t ts, stream_id;
	int ret;

	ret = cds_lfht_is_node_deleted(&stream->node.node);
	if (ret) {
		goto end;
	}

	ret = lttng_ustconsumer_get_current_timestamp(stream, &ts);
	if (ret < 0) {
		ERR("Failed to get the current timestamp");
		goto end;
	}
	lttng_ustconsumer_flush_buffer(stream, 1);
	ret = lttng_ustconsumer_take_snapshot(stream);
	if (ret < 0) {
		if (ret != -EAGAIN) {
			ERR("Taking UST snapshot");
			ret = -1;
			goto end;
		}
		ret = lttng_ustconsumer_get_stream_id(stream, &stream_id);
		if (ret < 0) {
			PERROR("ustctl_get_stream_id");
			goto end;
		}
		DBG("Stream %" PRIu64 " empty, sending beacon", stream->key);
		ret = send_empty_index(stream, ts, stream_id);
		if (ret < 0) {
			goto end;
		}
	}
	ret = 0;
end:
	return ret;
}

static int check_ust_stream(struct lttng_consumer_stream *stream)
{
	int ret;

	assert(stream);
	assert(stream->ustream);
	/*
	 * While holding the stream mutex, try to take a snapshot, if it
	 * succeeds, it means that data is ready to be sent, just let the data
	 * thread handle that. Otherwise, if the snapshot returns EAGAIN, it
	 * means that there is no data to read after the flush, so we can
	 * safely send the empty index.
	 *
	 * Doing a trylock and checking if waiting on metadata if
	 * trylock fails. Bail out of the stream is indeed waiting for
	 * metadata to be pushed. Busy wait on trylock otherwise.
	 */
	for (;;) {
		ret = pthread_mutex_trylock(&stream->lock);
		switch (ret) {
		case 0:
			break;	/* We have the lock. */
		case EBUSY:
			pthread_mutex_lock(&stream->metadata_timer_lock);
			if (stream->waiting_on_metadata) {
				ret = 0;
				stream->missed_metadata_flush = true;
				pthread_mutex_unlock(&stream->metadata_timer_lock);
				goto end;	/* Bail out. */
			}
			pthread_mutex_unlock(&stream->metadata_timer_lock);
			/* Try again. */
			caa_cpu_relax();
			continue;
		default:
			ERR("Unexpected pthread_mutex_trylock error %d", ret);
			ret = -1;
			goto end;
		}
		break;
	}
	ret = consumer_flush_ust_index(stream);
	pthread_mutex_unlock(&stream->lock);
end:
	return ret;
}

/*
 * Execute action on a live timer
 */
static void live_timer(struct lttng_consumer_local_data *ctx,
		int sig, siginfo_t *si)
{
	int ret;
	struct lttng_consumer_channel *channel;
	struct lttng_consumer_stream *stream;
	struct lttng_ht *ht;
	struct lttng_ht_iter iter;

	channel = si->si_value.sival_ptr;
	assert(channel);

	if (channel->switch_timer_error) {
		goto error;
	}
	ht = consumer_data.stream_per_chan_id_ht;

	DBG("Live timer for channel %" PRIu64, channel->key);

	rcu_read_lock();
	switch (ctx->type) {
	case LTTNG_CONSUMER32_UST:
	case LTTNG_CONSUMER64_UST:
		cds_lfht_for_each_entry_duplicate(ht->ht,
				ht->hash_fct(&channel->key, lttng_ht_seed),
				ht->match_fct, &channel->key, &iter.iter,
				stream, node_channel_id.node) {
			ret = check_ust_stream(stream);
			if (ret < 0) {
				goto error_unlock;
			}
		}
		break;
	case LTTNG_CONSUMER_KERNEL:
		cds_lfht_for_each_entry_duplicate(ht->ht,
				ht->hash_fct(&channel->key, lttng_ht_seed),
				ht->match_fct, &channel->key, &iter.iter,
				stream, node_channel_id.node) {
			ret = check_kernel_stream(stream);
			if (ret < 0) {
				goto error_unlock;
			}
		}
		break;
	case LTTNG_CONSUMER_UNKNOWN:
		assert(0);
		break;
	}

error_unlock:
	rcu_read_unlock();

error:
	return;
}

static
void consumer_timer_signal_thread_qs(unsigned int signr)
{
	sigset_t pending_set;
	int ret;

	/*
	 * We need to be the only thread interacting with the thread
	 * that manages signals for teardown synchronization.
	 */
	pthread_mutex_lock(&timer_signal.lock);

	/* Ensure we don't have any signal queued for this channel. */
	for (;;) {
		ret = sigemptyset(&pending_set);
		if (ret == -1) {
			PERROR("sigemptyset");
		}
		ret = sigpending(&pending_set);
		if (ret == -1) {
			PERROR("sigpending");
		}
		if (!sigismember(&pending_set, signr)) {
			break;
		}
		caa_cpu_relax();
	}

	/*
	 * From this point, no new signal handler will be fired that would try to
	 * access "chan". However, we still need to wait for any currently
	 * executing handler to complete.
	 */
	cmm_smp_mb();
	CMM_STORE_SHARED(timer_signal.qs_done, 0);
	cmm_smp_mb();

	/*
	 * Kill with LTTNG_CONSUMER_SIG_TEARDOWN, so signal management thread wakes
	 * up.
	 */
	kill(getpid(), LTTNG_CONSUMER_SIG_TEARDOWN);

	while (!CMM_LOAD_SHARED(timer_signal.qs_done)) {
		caa_cpu_relax();
	}
	cmm_smp_mb();

	pthread_mutex_unlock(&timer_signal.lock);
}

/*
 * Start a timer channel timer which will fire at a given interval
 * (timer_interval_us)and fire a given signal (signal).
 *
 * Returns a negative value on error, 0 if a timer was created, and
 * a positive value if no timer was created (not an error).
 */
static
int consumer_channel_timer_start(timer_t *timer_id,
		struct lttng_consumer_channel *channel,
		unsigned int timer_interval_us, int signal)
{
	int ret = 0, delete_ret;
	struct sigevent sev;
	struct itimerspec its;

	assert(channel);
	assert(channel->key);

	if (timer_interval_us == 0) {
		/* No creation needed; not an error. */
		ret = 1;
		goto end;
	}

	sev.sigev_notify = SIGEV_SIGNAL;
	sev.sigev_signo = signal;
	sev.sigev_value.sival_ptr = channel;
	ret = timer_create(CLOCKID, &sev, timer_id);
	if (ret == -1) {
		PERROR("timer_create");
		goto end;
	}

	its.it_value.tv_sec = timer_interval_us / 1000000;
	its.it_value.tv_nsec = (timer_interval_us % 1000000) * 1000;
	its.it_interval.tv_sec = its.it_value.tv_sec;
	its.it_interval.tv_nsec = its.it_value.tv_nsec;

	ret = timer_settime(*timer_id, 0, &its, NULL);
	if (ret == -1) {
		PERROR("timer_settime");
		goto error_destroy_timer;
	}
end:
	return ret;
error_destroy_timer:
	delete_ret = timer_delete(*timer_id);
	if (delete_ret == -1) {
		PERROR("timer_delete");
	}
	goto end;
}

static
int consumer_channel_timer_stop(timer_t *timer_id, int signal)
{
	int ret = 0;

	ret = timer_delete(*timer_id);
	if (ret == -1) {
		PERROR("timer_delete");
		goto end;
	}

	consumer_timer_signal_thread_qs(signal);
	*timer_id = 0;
end:
	return ret;
}

/*
 * Set the channel's switch timer.
 */
void consumer_timer_switch_start(struct lttng_consumer_channel *channel,
		unsigned int switch_timer_interval_us)
{
	int ret;

	assert(channel);
	assert(channel->key);

	ret = consumer_channel_timer_start(&channel->switch_timer, channel,
			switch_timer_interval_us, LTTNG_CONSUMER_SIG_SWITCH);

	channel->switch_timer_enabled = !!(ret == 0);
}

/*
 * Stop and delete the channel's switch timer.
 */
void consumer_timer_switch_stop(struct lttng_consumer_channel *channel)
{
	int ret;

	assert(channel);

	ret = consumer_channel_timer_stop(&channel->switch_timer,
			LTTNG_CONSUMER_SIG_SWITCH);
	if (ret == -1) {
		ERR("Failed to stop switch timer");
	}

	channel->switch_timer_enabled = 0;
}

/*
 * Set the channel's live timer.
 */
void consumer_timer_live_start(struct lttng_consumer_channel *channel,
		unsigned int live_timer_interval_us)
{
	int ret;

	assert(channel);
	assert(channel->key);

	ret = consumer_channel_timer_start(&channel->live_timer, channel,
			live_timer_interval_us, LTTNG_CONSUMER_SIG_LIVE);

	channel->live_timer_enabled = !!(ret == 0);
}

/*
 * Stop and delete the channel's live timer.
 */
void consumer_timer_live_stop(struct lttng_consumer_channel *channel)
{
	int ret;

	assert(channel);

	ret = consumer_channel_timer_stop(&channel->live_timer,
			LTTNG_CONSUMER_SIG_LIVE);
	if (ret == -1) {
		ERR("Failed to stop live timer");
	}

	channel->live_timer_enabled = 0;
}

/*
 * Set the channel's monitoring timer.
 *
 * Returns a negative value on error, 0 if a timer was created, and
 * a positive value if no timer was created (not an error).
 */
int consumer_timer_monitor_start(struct lttng_consumer_channel *channel,
		unsigned int monitor_timer_interval_us)
{
	int ret;

	assert(channel);
	assert(channel->key);
	assert(!channel->monitor_timer_enabled);

	ret = consumer_channel_timer_start(&channel->monitor_timer, channel,
			monitor_timer_interval_us, LTTNG_CONSUMER_SIG_MONITOR);
	channel->monitor_timer_enabled = !!(ret == 0);
	return ret;
}

/*
 * Stop and delete the channel's monitoring timer.
 */
int consumer_timer_monitor_stop(struct lttng_consumer_channel *channel)
{
	int ret;

	assert(channel);
	assert(channel->monitor_timer_enabled);

	ret = consumer_channel_timer_stop(&channel->monitor_timer,
			LTTNG_CONSUMER_SIG_MONITOR);
	if (ret == -1) {
		ERR("Failed to stop live timer");
		goto end;
	}

	channel->monitor_timer_enabled = 0;
end:
	return ret;
}

/*
 * Block the RT signals for the entire process. It must be called from the
 * consumer main before creating the threads
 */
int consumer_signal_init(void)
{
	int ret;
	sigset_t mask;

	/* Block signal for entire process, so only our thread processes it. */
	setmask(&mask);
	ret = pthread_sigmask(SIG_BLOCK, &mask, NULL);
	if (ret) {
		errno = ret;
		PERROR("pthread_sigmask");
		return -1;
	}
	return 0;
}

static
int sample_channel_positions(struct lttng_consumer_channel *channel,
		uint64_t *_highest_use, uint64_t *_lowest_use,
		sample_positions_cb sample, get_consumed_cb get_consumed,
		get_produced_cb get_produced)
{
	int ret;
	struct lttng_ht_iter iter;
	struct lttng_consumer_stream *stream;
	bool empty_channel = true;
	uint64_t high = 0, low = UINT64_MAX;
	struct lttng_ht *ht = consumer_data.stream_per_chan_id_ht;

	rcu_read_lock();

	cds_lfht_for_each_entry_duplicate(ht->ht,
			ht->hash_fct(&channel->key, lttng_ht_seed),
			ht->match_fct, &channel->key,
			&iter.iter, stream, node_channel_id.node) {
		unsigned long produced, consumed, usage;

		empty_channel = false;

		pthread_mutex_lock(&stream->lock);
		if (cds_lfht_is_node_deleted(&stream->node.node)) {
			goto next;
		}

		ret = sample(stream);
		if (ret) {
			ERR("Failed to take buffer position snapshot in monitor timer (ret = %d)", ret);
			pthread_mutex_unlock(&stream->lock);
			goto end;
		}
		ret = get_consumed(stream, &consumed);
		if (ret) {
			ERR("Failed to get buffer consumed position in monitor timer");
			pthread_mutex_unlock(&stream->lock);
			goto end;
		}
		ret = get_produced(stream, &produced);
		if (ret) {
			ERR("Failed to get buffer produced position in monitor timer");
			pthread_mutex_unlock(&stream->lock);
			goto end;
		}

		usage = produced - consumed;
		high = (usage > high) ? usage : high;
		low = (usage < low) ? usage : low;
	next:
		pthread_mutex_unlock(&stream->lock);
	}

	*_highest_use = high;
	*_lowest_use = low;
end:
	rcu_read_unlock();
	if (empty_channel) {
		ret = -1;
	}
	return ret;
}

/*
 * Execute action on a monitor timer.
 */
static
void monitor_timer(struct lttng_consumer_local_data *ctx,
		struct lttng_consumer_channel *channel)
{
	int ret;
	int channel_monitor_pipe =
			consumer_timer_thread_get_channel_monitor_pipe();
	struct lttcomm_consumer_channel_monitor_msg msg = {
		.key = channel->key,
	};
	sample_positions_cb sample;
	get_consumed_cb get_consumed;
	get_produced_cb get_produced;

	assert(channel);

	if (channel_monitor_pipe < 0) {
		return;
	}

	switch (consumer_data.type) {
	case LTTNG_CONSUMER_KERNEL:
		sample = lttng_kconsumer_sample_snapshot_positions;
		get_consumed = lttng_kconsumer_get_consumed_snapshot;
		get_produced = lttng_kconsumer_get_produced_snapshot;
		break;
	case LTTNG_CONSUMER32_UST:
	case LTTNG_CONSUMER64_UST:
		sample = lttng_ustconsumer_sample_snapshot_positions;
		get_consumed = lttng_ustconsumer_get_consumed_snapshot;
		get_produced = lttng_ustconsumer_get_produced_snapshot;
		break;
	default:
		abort();
	}

	ret = sample_channel_positions(channel, &msg.highest, &msg.lowest,
			sample, get_consumed, get_produced);
	if (ret) {
		return;
	}

	/*
	 * Writes performed here are assumed to be atomic which is only
	 * guaranteed for sizes < than PIPE_BUF.
	 */
	assert(sizeof(msg) <= PIPE_BUF);

	do {
		ret = write(channel_monitor_pipe, &msg, sizeof(msg));
	} while (ret == -1 && errno == EINTR);
	if (ret == -1) {
		if (errno == EAGAIN) {
			/* Not an error, the sample is merely dropped. */
			DBG("Channel monitor pipe is full; dropping sample for channel key = %"PRIu64,
					channel->key);
		} else {
			PERROR("write to the channel monitor pipe");
		}
	} else {
		DBG("Sent channel monitoring sample for channel key %" PRIu64
				", (highest = %" PRIu64 ", lowest = %"PRIu64")",
				channel->key, msg.highest, msg.lowest);
	}
}

int consumer_timer_thread_get_channel_monitor_pipe(void)
{
	return uatomic_read(&channel_monitor_pipe);
}

int consumer_timer_thread_set_channel_monitor_pipe(int fd)
{
	int ret;

	ret = uatomic_cmpxchg(&channel_monitor_pipe, -1, fd);
	if (ret != -1) {
		ret = -1;
		goto end;
	}
	ret = 0;
end:
	return ret;
}

/*
 * This thread is the sighandler for signals LTTNG_CONSUMER_SIG_SWITCH,
 * LTTNG_CONSUMER_SIG_TEARDOWN, LTTNG_CONSUMER_SIG_LIVE, and
 * LTTNG_CONSUMER_SIG_MONITOR, LTTNG_CONSUMER_SIG_EXIT.
 */
void *consumer_timer_thread(void *data)
{
	int signr;
	sigset_t mask;
	siginfo_t info;
	struct lttng_consumer_local_data *ctx = data;

	rcu_register_thread();

	health_register(health_consumerd, HEALTH_CONSUMERD_TYPE_METADATA_TIMER);

	if (testpoint(consumerd_thread_metadata_timer)) {
		goto error_testpoint;
	}

	health_code_update();

	/* Only self thread will receive signal mask. */
	setmask(&mask);
	CMM_STORE_SHARED(timer_signal.tid, pthread_self());

	while (1) {
		health_code_update();

		health_poll_entry();
		signr = sigwaitinfo(&mask, &info);
		health_poll_exit();

		/*
		 * NOTE: cascading conditions are used instead of a switch case
		 * since the use of SIGRTMIN in the definition of the signals'
		 * values prevents the reduction to an integer constant.
		 */
		if (signr == -1) {
			if (errno != EINTR) {
				PERROR("sigwaitinfo");
			}
			continue;
		} else if (signr == LTTNG_CONSUMER_SIG_SWITCH) {
			metadata_switch_timer(ctx, info.si_signo, &info);
		} else if (signr == LTTNG_CONSUMER_SIG_TEARDOWN) {
			cmm_smp_mb();
			CMM_STORE_SHARED(timer_signal.qs_done, 1);
			cmm_smp_mb();
			DBG("Signal timer metadata thread teardown");
		} else if (signr == LTTNG_CONSUMER_SIG_LIVE) {
			live_timer(ctx, info.si_signo, &info);
		} else if (signr == LTTNG_CONSUMER_SIG_MONITOR) {
			struct lttng_consumer_channel *channel;

			channel = info.si_value.sival_ptr;
			monitor_timer(ctx, channel);
		} else if (signr == LTTNG_CONSUMER_SIG_EXIT) {
			assert(CMM_LOAD_SHARED(consumer_quit));
			goto end;
		} else {
			ERR("Unexpected signal %d\n", info.si_signo);
		}
	}

error_testpoint:
	/* Only reached in testpoint error */
	health_error();
end:
	health_unregister(health_consumerd);
	rcu_unregister_thread();
	return NULL;
}
