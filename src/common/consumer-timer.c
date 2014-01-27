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

#define _GNU_SOURCE
#include <assert.h>
#include <inttypes.h>
#include <signal.h>

#include <bin/lttng-consumerd/health-consumerd.h>
#include <common/common.h>
#include <common/kernel-ctl/kernel-ctl.h>
#include <common/kernel-consumer/kernel-consumer.h>
#include <common/consumer-stream.h>

#include "consumer-timer.h"
#include "consumer-testpoint.h"
#include "ust-consumer/ust-consumer.h"

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
}

/*
 * Execute action on a timer switch.
 *
 * Beware: metadata_switch_timer() should *never* take a mutex also held
 * while consumer_timer_switch_stop() is called. It would result in
 * deadlocks.
 */
static void metadata_switch_timer(struct lttng_consumer_local_data *ctx,
		int sig, siginfo_t *si, void *uc)
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

static int send_empty_index(struct lttng_consumer_stream *stream, uint64_t ts)
{
	int ret;
	struct ctf_packet_index index;

	memset(&index, 0, sizeof(index));
	index.timestamp_end = htobe64(ts);
	ret = consumer_stream_write_index(stream, &index);
	if (ret < 0) {
		goto error;
	}

error:
	return ret;
}

static int check_kernel_stream(struct lttng_consumer_stream *stream)
{
	uint64_t ts;
	int ret;

	/*
	 * While holding the stream mutex, try to take a snapshot, if it
	 * succeeds, it means that data is ready to be sent, just let the data
	 * thread handle that. Otherwise, if the snapshot returns EAGAIN, it
	 * means that there is no data to read after the flush, so we can
	 * safely send the empty index.
	 */
	pthread_mutex_lock(&stream->lock);
	ret = kernctl_get_current_timestamp(stream->wait_fd, &ts);
	if (ret < 0) {
		ERR("Failed to get the current timestamp");
		goto error_unlock;
	}
	ret = kernctl_buffer_flush(stream->wait_fd);
	if (ret < 0) {
		ERR("Failed to flush kernel stream");
		goto error_unlock;
	}
	ret = kernctl_snapshot(stream->wait_fd);
	if (ret < 0) {
		if (errno != EAGAIN) {
			ERR("Taking kernel snapshot");
			ret = -1;
			goto error_unlock;
		}
		DBG("Stream %" PRIu64 " empty, sending beacon", stream->key);
		ret = send_empty_index(stream, ts);
		if (ret < 0) {
			goto error_unlock;
		}
	}
	ret = 0;

error_unlock:
	pthread_mutex_unlock(&stream->lock);
	return ret;
}

static int check_ust_stream(struct lttng_consumer_stream *stream)
{
	uint64_t ts;
	int ret;

	assert(stream);
	assert(stream->ustream);
	/*
	 * While holding the stream mutex, try to take a snapshot, if it
	 * succeeds, it means that data is ready to be sent, just let the data
	 * thread handle that. Otherwise, if the snapshot returns EAGAIN, it
	 * means that there is no data to read after the flush, so we can
	 * safely send the empty index.
	 */
	pthread_mutex_lock(&stream->lock);
	ret = cds_lfht_is_node_deleted(&stream->node.node);
	if (ret) {
		goto error_unlock;
	}

	ret = lttng_ustconsumer_get_current_timestamp(stream, &ts);
	if (ret < 0) {
		ERR("Failed to get the current timestamp");
		goto error_unlock;
	}
	lttng_ustconsumer_flush_buffer(stream, 1);
	ret = lttng_ustconsumer_take_snapshot(stream);
	if (ret < 0) {
		if (ret != -EAGAIN) {
			ERR("Taking UST snapshot");
			ret = -1;
			goto error_unlock;
		}
		DBG("Stream %" PRIu64 " empty, sending beacon", stream->key);
		ret = send_empty_index(stream, ts);
		if (ret < 0) {
			goto error_unlock;
		}
	}
	ret = 0;

error_unlock:
	pthread_mutex_unlock(&stream->lock);
	return ret;
}

/*
 * Execute action on a live timer
 */
static void live_timer(struct lttng_consumer_local_data *ctx,
		int sig, siginfo_t *si, void *uc)
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
		if (!sigismember(&pending_set, LTTNG_CONSUMER_SIG_SWITCH)) {
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
 * Set the timer for periodical metadata flush.
 */
void consumer_timer_switch_start(struct lttng_consumer_channel *channel,
		unsigned int switch_timer_interval)
{
	int ret;
	struct sigevent sev;
	struct itimerspec its;

	assert(channel);
	assert(channel->key);

	if (switch_timer_interval == 0) {
		return;
	}

	sev.sigev_notify = SIGEV_SIGNAL;
	sev.sigev_signo = LTTNG_CONSUMER_SIG_SWITCH;
	sev.sigev_value.sival_ptr = channel;
	ret = timer_create(CLOCKID, &sev, &channel->switch_timer);
	if (ret == -1) {
		PERROR("timer_create");
	}
	channel->switch_timer_enabled = 1;

	its.it_value.tv_sec = switch_timer_interval / 1000000;
	its.it_value.tv_nsec = switch_timer_interval % 1000000;
	its.it_interval.tv_sec = its.it_value.tv_sec;
	its.it_interval.tv_nsec = its.it_value.tv_nsec;

	ret = timer_settime(channel->switch_timer, 0, &its, NULL);
	if (ret == -1) {
		PERROR("timer_settime");
	}
}

/*
 * Stop and delete timer.
 */
void consumer_timer_switch_stop(struct lttng_consumer_channel *channel)
{
	int ret;

	assert(channel);

	ret = timer_delete(channel->switch_timer);
	if (ret == -1) {
		PERROR("timer_delete");
	}

	consumer_timer_signal_thread_qs(LTTNG_CONSUMER_SIG_SWITCH);

	channel->switch_timer = 0;
	channel->switch_timer_enabled = 0;
}

/*
 * Set the timer for the live mode.
 */
void consumer_timer_live_start(struct lttng_consumer_channel *channel,
		int live_timer_interval)
{
	int ret;
	struct sigevent sev;
	struct itimerspec its;

	assert(channel);
	assert(channel->key);

	if (live_timer_interval <= 0) {
		return;
	}

	sev.sigev_notify = SIGEV_SIGNAL;
	sev.sigev_signo = LTTNG_CONSUMER_SIG_LIVE;
	sev.sigev_value.sival_ptr = channel;
	ret = timer_create(CLOCKID, &sev, &channel->live_timer);
	if (ret == -1) {
		PERROR("timer_create");
	}
	channel->live_timer_enabled = 1;

	its.it_value.tv_sec = live_timer_interval / 1000000;
	its.it_value.tv_nsec = live_timer_interval % 1000000;
	its.it_interval.tv_sec = its.it_value.tv_sec;
	its.it_interval.tv_nsec = its.it_value.tv_nsec;

	ret = timer_settime(channel->live_timer, 0, &its, NULL);
	if (ret == -1) {
		PERROR("timer_settime");
	}
}

/*
 * Stop and delete timer.
 */
void consumer_timer_live_stop(struct lttng_consumer_channel *channel)
{
	int ret;

	assert(channel);

	ret = timer_delete(channel->live_timer);
	if (ret == -1) {
		PERROR("timer_delete");
	}

	consumer_timer_signal_thread_qs(LTTNG_CONSUMER_SIG_LIVE);

	channel->live_timer = 0;
	channel->live_timer_enabled = 0;
}

/*
 * Block the RT signals for the entire process. It must be called from the
 * consumer main before creating the threads
 */
void consumer_signal_init(void)
{
	int ret;
	sigset_t mask;

	/* Block signal for entire process, so only our thread processes it. */
	setmask(&mask);
	ret = pthread_sigmask(SIG_BLOCK, &mask, NULL);
	if (ret) {
		errno = ret;
		PERROR("pthread_sigmask");
	}
}

/*
 * This thread is the sighandler for signals LTTNG_CONSUMER_SIG_SWITCH,
 * LTTNG_CONSUMER_SIG_TEARDOWN and LTTNG_CONSUMER_SIG_LIVE.
 */
void *consumer_timer_thread(void *data)
{
	int signr;
	sigset_t mask;
	siginfo_t info;
	struct lttng_consumer_local_data *ctx = data;

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
		if (signr == -1) {
			if (errno != EINTR) {
				PERROR("sigwaitinfo");
			}
			continue;
		} else if (signr == LTTNG_CONSUMER_SIG_SWITCH) {
			metadata_switch_timer(ctx, info.si_signo, &info, NULL);
		} else if (signr == LTTNG_CONSUMER_SIG_TEARDOWN) {
			cmm_smp_mb();
			CMM_STORE_SHARED(timer_signal.qs_done, 1);
			cmm_smp_mb();
			DBG("Signal timer metadata thread teardown");
		} else if (signr == LTTNG_CONSUMER_SIG_LIVE) {
			live_timer(ctx, info.si_signo, &info, NULL);
		} else {
			ERR("Unexpected signal %d\n", info.si_signo);
		}
	}

error_testpoint:
	/* Only reached in testpoint error */
	health_error();
	health_unregister(health_consumerd);

	/* Never return */
	return NULL;
}
