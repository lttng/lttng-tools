/*
 * Copyright (C) 2017 - Julien Desfossez <jdesfossez@efficios.com>
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

#include "sessiond-timer.h"
#include "health-sessiond.h"
#include "rotation-thread.h"

static
struct timer_signal_data timer_signal = {
	.tid = 0,
	.qs_done = 0,
	.lock = PTHREAD_MUTEX_INITIALIZER,
};

/*
 * Set custom signal mask to current thread.
 */
static
void setmask(sigset_t *mask)
{
	int ret;

	ret = sigemptyset(mask);
	if (ret) {
		PERROR("sigemptyset");
	}
	ret = sigaddset(mask, LTTNG_SESSIOND_SIG_TEARDOWN);
	if (ret) {
		PERROR("sigaddset teardown");
	}
	ret = sigaddset(mask, LTTNG_SESSIOND_SIG_EXIT);
	if (ret) {
		PERROR("sigaddset exit");
	}
	ret = sigaddset(mask, LTTNG_SESSIOND_SIG_ROTATE_PENDING);
	if (ret) {
		PERROR("sigaddset switch");
	}
}

/*
 * This is the same function as consumer_timer_signal_thread_qs, when it
 * returns, it means that no timer signr is currently pending or being handled
 * by the timer thread. This cannot be called from the timer thread.
 */
static
void sessiond_timer_signal_thread_qs(unsigned int signr)
{
	sigset_t pending_set;
	int ret;

	/*
	 * We need to be the only thread interacting with the thread
	 * that manages signals for teardown synchronization.
	 */
	pthread_mutex_lock(&timer_signal.lock);

	/* Ensure we don't have any signal queued for this session. */
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
	 * access "session". However, we still need to wait for any currently
	 * executing handler to complete.
	 */
	cmm_smp_mb();
	CMM_STORE_SHARED(timer_signal.qs_done, 0);
	cmm_smp_mb();

	/*
	 * Kill with LTTNG_SESSIOND_SIG_TEARDOWN, so signal management thread
	 * wakes up.
	 */
	kill(getpid(), LTTNG_SESSIOND_SIG_TEARDOWN);

	while (!CMM_LOAD_SHARED(timer_signal.qs_done)) {
		caa_cpu_relax();
	}
	cmm_smp_mb();

	pthread_mutex_unlock(&timer_signal.lock);
}

/*
 * Start a timer on a session that will fire at a given interval
 * (timer_interval_us) and fire a given signal (signal).
 *
 * Returns a negative value on error, 0 if a timer was created, and
 * a positive value if no timer was created (not an error).
 */
static
int session_timer_start(timer_t *timer_id, struct ltt_session *session,
		unsigned int timer_interval_us, int signal, bool one_shot)
{
	int ret = 0, delete_ret;
	struct sigevent sev;
	struct itimerspec its;

	assert(session);

	sev.sigev_notify = SIGEV_SIGNAL;
	sev.sigev_signo = signal;
	sev.sigev_value.sival_ptr = session;
	ret = timer_create(CLOCKID, &sev, timer_id);
	if (ret == -1) {
		PERROR("timer_create");
		goto end;
	}

	its.it_value.tv_sec = timer_interval_us / 1000000;
	its.it_value.tv_nsec = (timer_interval_us % 1000000) * 1000;
	if (one_shot) {
		its.it_interval.tv_sec = 0;
		its.it_interval.tv_nsec = 0;
	} else {
		its.it_interval.tv_sec = its.it_value.tv_sec;
		its.it_interval.tv_nsec = its.it_value.tv_nsec;
	}

	ret = timer_settime(*timer_id, 0, &its, NULL);
	if (ret == -1) {
		PERROR("timer_settime");
		goto error_destroy_timer;
	}
	goto end;

error_destroy_timer:
	delete_ret = timer_delete(*timer_id);
	if (delete_ret == -1) {
		PERROR("timer_delete");
	}

end:
	return ret;
}

static
int session_timer_stop(timer_t *timer_id, int signal)
{
	int ret = 0;

	ret = timer_delete(*timer_id);
	if (ret == -1) {
		PERROR("timer_delete");
		goto end;
	}

	sessiond_timer_signal_thread_qs(signal);
	*timer_id = 0;
end:
	return ret;
}

int sessiond_timer_rotate_pending_start(struct ltt_session *session,
		unsigned int interval_us)
{
	int ret;

	DBG("Enabling rotate pending timer on session %" PRIu64, session->id);
	/*
	 * We arm this timer in a one-shot mode so we don't have to disable it
	 * explicitly (which could deadlock if the timer thread is blocked writing
	 * in the rotation_timer_pipe).
	 * Instead, we re-arm it if needed after the rotation_pending check as
	 * returned. Also, this timer is usually only needed once, so there is no
	 * need to go through the whole signal teardown scheme everytime.
	 */
	ret = session_timer_start(&session->rotate_relay_pending_timer,
			session, interval_us,
			LTTNG_SESSIOND_SIG_ROTATE_PENDING,
			/* one-shot */ true);
	if (ret == 0) {
		session->rotate_relay_pending_timer_enabled = true;
	}

	return ret;
}

/*
 * Stop and delete the channel's live timer.
 * Called with session and session_list locks held.
 */
void sessiond_timer_rotate_pending_stop(struct ltt_session *session)
{
	int ret;

	assert(session);

	DBG("Disabling timer rotate pending on session %" PRIu64, session->id);
	ret = session_timer_stop(&session->rotate_relay_pending_timer,
			LTTNG_SESSIOND_SIG_ROTATE_PENDING);
	if (ret == -1) {
		ERR("Failed to stop rotate_pending timer");
	}

	session->rotate_relay_pending_timer_enabled = false;
}

/*
 * Block the RT signals for the entire process. It must be called from the
 * sessiond main before creating the threads
 */
int sessiond_timer_signal_init(void)
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

/*
 * Called with the rotation_timer_queue lock held.
 * Return true if the same timer job already exists in the queue, false if not.
 */
static
bool check_duplicate_timer_job(struct timer_thread_parameters *ctx,
		struct ltt_session *session, unsigned int signal)
{
	bool ret = false;
	struct sessiond_rotation_timer *node;

	rcu_read_lock();
	cds_list_for_each_entry(node, &ctx->rotation_timer_queue->list, head) {
		if (node->session_id == session->id && node->signal == signal) {
			ret = true;
			goto end;
		}
	}

end:
	rcu_read_unlock();
	return ret;
}

/*
 * Add the session ID and signal value to the rotation_timer_queue if it is
 * not already there and wakeup the rotation thread. The rotation thread
 * empties the whole queue everytime it is woken up. The event_pipe is
 * non-blocking, if it would block, we just return because we know the
 * rotation thread will be awaken anyway.
 */
static
int enqueue_timer_rotate_job(struct timer_thread_parameters *ctx,
		struct ltt_session *session, unsigned int signal)
{
	int ret;
	char *c = "!";
	struct sessiond_rotation_timer *timer_data = NULL;

	pthread_mutex_lock(&ctx->rotation_timer_queue->lock);
	if (check_duplicate_timer_job(ctx, session, signal)) {
		/*
		 * This timer job is already pending, we don't need to add
		 * it.
		 */
		ret = 0;
		goto end;
	}

	timer_data = zmalloc(sizeof(struct sessiond_rotation_timer));
	if (!timer_data) {
		PERROR("Allocation of timer data");
		ret = -1;
		goto end;
	}
	timer_data->session_id = session->id;
	timer_data->signal = signal;
	cds_list_add_tail(&timer_data->head,
			&ctx->rotation_timer_queue->list);

	ret = lttng_write(
			lttng_pipe_get_writefd(ctx->rotation_timer_queue->event_pipe),
			c, 1);
	if (ret < 0) {
		/*
		 * We do not want to block in the timer handler, the job has been
		 * enqueued in the list, the wakeup pipe is probably full, the job
		 * will be processed when the rotation_thread catches up.
		 */
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			ret = 0;
			goto end;
		}
		PERROR("Timer wakeup rotation thread");
		goto end;
	}

	ret = 0;

end:
	pthread_mutex_unlock(&ctx->rotation_timer_queue->lock);
	return ret;
}

/*
 * Ask the rotation thread to check if the last rotation started in this
 * session is still pending on the relay.
 */
static
void relay_rotation_pending_timer(struct timer_thread_parameters *ctx,
		int sig, siginfo_t *si)
{
	int ret;
	struct ltt_session *session = si->si_value.sival_ptr;
	assert(session);

	ret = enqueue_timer_rotate_job(ctx, session, LTTNG_SESSIOND_SIG_ROTATE_PENDING);
	if (ret) {
		PERROR("wakeup rotate pipe");
	}
}

/*
 * This thread is the sighandler for the timer signals.
 */
void *sessiond_timer_thread(void *data)
{
	int signr;
	sigset_t mask;
	siginfo_t info;
	struct timer_thread_parameters *ctx = data;

	rcu_register_thread();
	rcu_thread_online();

	health_register(health_sessiond, HEALTH_SESSIOND_TYPE_TIMER);

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
		} else if (signr == LTTNG_SESSIOND_SIG_TEARDOWN) {
			cmm_smp_mb();
			CMM_STORE_SHARED(timer_signal.qs_done, 1);
			cmm_smp_mb();
			DBG("Signal timer metadata thread teardown");
		} else if (signr == LTTNG_SESSIOND_SIG_EXIT) {
			goto end;
		} else if (signr == LTTNG_SESSIOND_SIG_ROTATE_PENDING) {
			relay_rotation_pending_timer(ctx, info.si_signo, &info);
		} else {
			ERR("Unexpected signal %d\n", info.si_signo);
		}
	}

end:
	DBG("[timer-thread] Exit");
	health_unregister(health_sessiond);
	rcu_thread_offline();
	rcu_unregister_thread();
	return NULL;
}
