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

#include <common/common.h>

#include "consumer-timer.h"
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
		PERROR("sigaddset");
	}
	ret = sigaddset(mask, LTTNG_CONSUMER_SIG_TEARDOWN);
	if (ret) {
		PERROR("sigaddset");
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
		ret = lttng_ustconsumer_request_metadata(ctx, channel, 1);
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
 * This thread is the sighandler for signals LTTNG_CONSUMER_SIG_SWITCH and
 * LTTNG_CONSUMER_SIG_TEARDOWN that are emitted by the periodic timer to check
 * if new metadata is available.
 */
void *consumer_timer_metadata_thread(void *data)
{
	int signr;
	sigset_t mask;
	siginfo_t info;
	struct lttng_consumer_local_data *ctx = data;

	/* Only self thread will receive signal mask. */
	setmask(&mask);
	CMM_STORE_SHARED(timer_signal.tid, pthread_self());

	while (1) {
		signr = sigwaitinfo(&mask, &info);
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
		} else {
			ERR("Unexpected signal %d\n", info.si_signo);
		}
	}

	return NULL;
}
