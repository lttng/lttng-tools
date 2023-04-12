/*
 * Copyright (C) 2017 Julien Desfossez <jdesfossez@efficios.com>
 * Copyright (C) 2018 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#define _LGPL_SOURCE
#include "health-sessiond.hpp"
#include "rotation-thread.hpp"
#include "thread.hpp"
#include "timer.hpp"

#include <inttypes.h>
#include <signal.h>

#define LTTNG_SESSIOND_SIG_QS			  (SIGRTMIN + 10)
#define LTTNG_SESSIOND_SIG_EXIT			  (SIGRTMIN + 11)
#define LTTNG_SESSIOND_SIG_PENDING_ROTATION_CHECK (SIGRTMIN + 12)
#define LTTNG_SESSIOND_SIG_SCHEDULED_ROTATION	  (SIGRTMIN + 13)

#define UINT_TO_PTR(value)                            \
	({                                            \
		LTTNG_ASSERT((value) <= UINTPTR_MAX); \
		(void *) (uintptr_t) (value);         \
	})
#define PTR_TO_UINT(ptr) ((uintptr_t) (ptr))

namespace {
/*
 * Handle timer teardown race wrt memory free of private data by sessiond
 * signals are handled by a single thread, which permits a synchronization
 * point between handling of each signal. Internal lock ensures mutual
 * exclusion.
 */
struct timer_signal_data {
	/* Thread managing signals. */
	pthread_t tid;
	int qs_done;
	pthread_mutex_t lock;
} timer_signal = {
	.tid = 0,
	.qs_done = 0,
	.lock = PTHREAD_MUTEX_INITIALIZER,
};
} /* namespace */

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
	ret = sigaddset(mask, LTTNG_SESSIOND_SIG_QS);
	if (ret) {
		PERROR("sigaddset teardown");
	}
	ret = sigaddset(mask, LTTNG_SESSIOND_SIG_EXIT);
	if (ret) {
		PERROR("sigaddset exit");
	}
	ret = sigaddset(mask, LTTNG_SESSIOND_SIG_PENDING_ROTATION_CHECK);
	if (ret) {
		PERROR("sigaddset pending rotation check");
	}
	ret = sigaddset(mask, LTTNG_SESSIOND_SIG_SCHEDULED_ROTATION);
	if (ret) {
		PERROR("sigaddset scheduled rotation");
	}
}

/*
 * This is the same function as timer_signal_thread_qs, when it
 * returns, it means that no timer signr is currently pending or being handled
 * by the timer thread. This cannot be called from the timer thread.
 */
static void timer_signal_thread_qs(unsigned int signr)
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
	 * Kill with LTTNG_SESSIOND_SIG_QS, so signal management thread
	 * wakes up.
	 */
	kill(getpid(), LTTNG_SESSIOND_SIG_QS);

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
static int timer_start(timer_t *timer_id,
		       struct ltt_session *session,
		       unsigned int timer_interval_us,
		       int signal,
		       bool one_shot)
{
	int ret = 0, delete_ret;
	struct sigevent sev = {};
	struct itimerspec its;

	sev.sigev_notify = SIGEV_SIGNAL;
	sev.sigev_signo = signal;
	sev.sigev_value.sival_ptr = session;
	ret = timer_create(CLOCK_MONOTONIC, &sev, timer_id);
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

	ret = timer_settime(*timer_id, 0, &its, nullptr);
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

static int timer_stop(timer_t *timer_id, int signal)
{
	int ret = 0;

	ret = timer_delete(*timer_id);
	if (ret == -1) {
		PERROR("timer_delete");
		goto end;
	}

	timer_signal_thread_qs(signal);
	*timer_id = nullptr;
end:
	return ret;
}

int timer_session_rotation_pending_check_start(struct ltt_session *session,
					       unsigned int interval_us)
{
	int ret;

	if (!session_get(session)) {
		ret = -1;
		goto end;
	}
	DBG("Enabling session rotation pending check timer on session %" PRIu64, session->id);
	/*
	 * We arm this timer in a one-shot mode so we don't have to disable it
	 * explicitly (which could deadlock if the timer thread is blocked
	 * writing in the rotation_timer_pipe).
	 *
	 * Instead, we re-arm it if needed after the rotation_pending check as
	 * returned. Also, this timer is usually only needed once, so there is
	 * no need to go through the whole signal teardown scheme everytime.
	 */
	ret = timer_start(&session->rotation_pending_check_timer,
			  session,
			  interval_us,
			  LTTNG_SESSIOND_SIG_PENDING_ROTATION_CHECK,
			  /* one-shot */ true);
	if (ret == 0) {
		session->rotation_pending_check_timer_enabled = true;
	}
end:
	return ret;
}

/*
 * Call with session and session_list locks held.
 */
int timer_session_rotation_pending_check_stop(ltt_session& session)
{
	int ret;

	LTTNG_ASSERT(session.rotation_pending_check_timer_enabled);

	DBG("Disabling session rotation pending check timer on session %" PRIu64, session.id);
	ret = timer_stop(&session.rotation_pending_check_timer,
			 LTTNG_SESSIOND_SIG_PENDING_ROTATION_CHECK);
	if (ret == -1) {
		ERR("Failed to stop rotate_pending_check timer");
	} else {
		session.rotation_pending_check_timer_enabled = false;
		/*
		 * The timer's reference to the session can be released safely.
		 */
		session_put(&session);
	}

	return ret;
}

/*
 * Call with session and session_list locks held.
 */
int timer_session_rotation_schedule_timer_start(struct ltt_session *session,
						unsigned int interval_us)
{
	int ret;

	if (!session_get(session)) {
		ret = -1;
		goto end;
	}
	DBG("Enabling scheduled rotation timer on session \"%s\" (%ui %s)",
	    session->name,
	    interval_us,
	    USEC_UNIT);
	ret = timer_start(&session->rotation_schedule_timer,
			  session,
			  interval_us,
			  LTTNG_SESSIOND_SIG_SCHEDULED_ROTATION,
			  /* one-shot */ false);
	if (ret < 0) {
		goto end;
	}
	session->rotation_schedule_timer_enabled = true;
end:
	return ret;
}

/*
 * Call with session and session_list locks held.
 */
int timer_session_rotation_schedule_timer_stop(struct ltt_session *session)
{
	int ret = 0;

	LTTNG_ASSERT(session);

	if (!session->rotation_schedule_timer_enabled) {
		goto end;
	}

	DBG("Disabling scheduled rotation timer on session %s", session->name);
	ret = timer_stop(&session->rotation_schedule_timer, LTTNG_SESSIOND_SIG_SCHEDULED_ROTATION);
	if (ret < 0) {
		ERR("Failed to stop scheduled rotation timer of session \"%s\"", session->name);
		goto end;
	}

	session->rotation_schedule_timer_enabled = false;
	/* The timer's reference to the session can be released safely. */
	session_put(session);
	ret = 0;
end:
	return ret;
}

/*
 * Block the RT signals for the entire process. It must be called from the
 * sessiond main before creating the threads
 */
int timer_signal_init()
{
	int ret;
	sigset_t mask;

	/* Block signal for entire process, so only our thread processes it. */
	setmask(&mask);
	ret = pthread_sigmask(SIG_BLOCK, &mask, nullptr);
	if (ret) {
		errno = ret;
		PERROR("pthread_sigmask");
		return -1;
	}
	return 0;
}

/*
 * This thread is the sighandler for the timer signals.
 */
static void *thread_timer(void *data)
{
	int signr;
	sigset_t mask;
	siginfo_t info;
	struct timer_thread_parameters *ctx = (timer_thread_parameters *) data;

	rcu_register_thread();
	rcu_thread_online();

	health_register(the_health_sessiond, HEALTH_SESSIOND_TYPE_TIMER);
	health_code_update();

	/* Only self thread will receive signal mask. */
	setmask(&mask);
	CMM_STORE_SHARED(timer_signal.tid, pthread_self());

	while (true) {
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
		} else if (signr == LTTNG_SESSIOND_SIG_QS) {
			cmm_smp_mb();
			CMM_STORE_SHARED(timer_signal.qs_done, 1);
			cmm_smp_mb();
		} else if (signr == LTTNG_SESSIOND_SIG_EXIT) {
			goto end;
		} else if (signr == LTTNG_SESSIOND_SIG_PENDING_ROTATION_CHECK) {
			struct ltt_session *session =
				(struct ltt_session *) info.si_value.sival_ptr;

			rotation_thread_enqueue_job(
				ctx->rotation_thread_job_queue,
				lttng::sessiond::rotation_thread_job_type::CHECK_PENDING_ROTATION,
				session);
		} else if (signr == LTTNG_SESSIOND_SIG_SCHEDULED_ROTATION) {
			rotation_thread_enqueue_job(
				ctx->rotation_thread_job_queue,
				lttng::sessiond::rotation_thread_job_type::SCHEDULED_ROTATION,
				(struct ltt_session *) info.si_value.sival_ptr);
			/*
			 * The scheduled periodic rotation timer is not in
			 * "one-shot" mode. The reference to the session is not
			 * released since the timer is still enabled and can
			 * still fire.
			 */
		} else {
			ERR("Unexpected signal %d", info.si_signo);
		}
	}

end:
	DBG("Thread exit");
	health_unregister(the_health_sessiond);
	rcu_thread_offline();
	rcu_unregister_thread();
	return nullptr;
}

static bool shutdown_timer_thread(void *data __attribute__((unused)))
{
	return kill(getpid(), LTTNG_SESSIOND_SIG_EXIT) == 0;
}

bool launch_timer_thread(struct timer_thread_parameters *timer_thread_parameters)
{
	struct lttng_thread *thread;

	thread = lttng_thread_create(
		"Timer", thread_timer, shutdown_timer_thread, nullptr, timer_thread_parameters);
	if (!thread) {
		goto error;
	}
	lttng_thread_put(thread);
	return true;
error:
	return false;
}
