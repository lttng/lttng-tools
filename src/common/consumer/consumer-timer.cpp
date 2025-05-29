/*
 * SPDX-FileCopyrightText: 2012 Julien Desfossez <julien.desfossez@efficios.com>
 * SPDX-FileCopyrightText: 2012 David Goulet <dgoulet@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#define _LGPL_SOURCE
#include <common/common.hpp>
#include <common/compat/endian.hpp>
#include <common/consumer/consumer-stream.hpp>
#include <common/consumer/consumer-testpoint.hpp>
#include <common/consumer/consumer-timer.hpp>
#include <common/consumer/live-timer-task.hpp>
#include <common/consumer/metadata-switch-timer-task.hpp>
#include <common/consumer/monitor-timer-task.hpp>
#include <common/kernel-consumer/kernel-consumer.hpp>
#include <common/kernel-ctl/kernel-ctl.hpp>
#include <common/urcu.hpp>
#include <common/ust-consumer/ust-consumer.hpp>

#include <bin/lttng-consumerd/health-consumerd.hpp>
#include <inttypes.h>
#include <signal.h>

using flush_index_cb = int (*)(struct lttng_consumer_stream *);

static struct timer_signal_data timer_signal = {
	.tid = 0,
	.setup_done = 0,
	.qs_done = 0,
	.lock = PTHREAD_MUTEX_INITIALIZER,
};

namespace {
bool is_userspace_consumer() noexcept
{
	switch (the_consumer_data.type) {
	case LTTNG_CONSUMER32_UST:
	case LTTNG_CONSUMER64_UST:
		return true;
	case LTTNG_CONSUMER_KERNEL:
	case LTTNG_CONSUMER_UNKNOWN:
		return false;
	default:
		abort();
	}
}
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
	ret = sigaddset(mask, LTTNG_CONSUMER_SIG_SWITCH);
	if (ret) {
		PERROR("sigaddset switch");
	}
	ret = sigaddset(mask, LTTNG_CONSUMER_SIG_TEARDOWN);
	if (ret) {
		PERROR("sigaddset teardown");
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

static int the_channel_monitor_pipe = -1;

static void consumer_timer_signal_thread_qs(unsigned int signr)
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
static int consumer_channel_timer_start(timer_t *timer_id,
					struct lttng_consumer_channel *channel,
					unsigned int timer_interval_us,
					int signal)
{
	int ret = 0, delete_ret;
	struct sigevent sev = {};
	struct itimerspec its;

	LTTNG_ASSERT(channel);
	LTTNG_ASSERT(channel->key);
	LTTNG_ASSERT(!channel->is_deleted);

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

	ret = timer_settime(*timer_id, 0, &its, nullptr);
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

static int consumer_channel_timer_stop(timer_t *timer_id, int signal)
{
	int ret = 0;

	ret = timer_delete(*timer_id);
	if (ret == -1) {
		PERROR("timer_delete");
		goto end;
	}

	consumer_timer_signal_thread_qs(signal);
	*timer_id = nullptr;
end:
	return ret;
}

/*
 * Set the channel's switch timer.
 */
void consumer_timer_switch_start(struct lttng_consumer_channel *channel,
				 unsigned int switch_timer_interval_us,
				 protected_socket& sessiond_metadata_socket,
				 int consumer_error_socket_fd)
{
	LTTNG_ASSERT(channel);
	LTTNG_ASSERT(channel->key);
	LTTNG_ASSERT(!channel->is_deleted);

	if (!is_userspace_consumer() || switch_timer_interval_us == 0) {
		return;
	}

	try {
		channel->metadata_switch_timer_task =
			std::make_shared<lttng::consumer::metadata_switch_timer_task>(
				std::chrono::microseconds(switch_timer_interval_us),
				*channel,
				sessiond_metadata_socket,
				consumer_error_socket_fd);
	} catch (const std::bad_alloc& e) {
		ERR_FMT("Failed to allocate memory for metadata switch timer task: {}", e.what());
		return;
	}

	const auto ret = consumer_channel_timer_start(&channel->switch_timer,
						      channel,
						      switch_timer_interval_us,
						      LTTNG_CONSUMER_SIG_SWITCH);
	if (ret) {
		ERR_FMT("Failed to start metadata switch timer: session_id={}, channel_key={}",
			channel->session_id,
			channel->key);

		channel->metadata_switch_timer_task.reset();
	}
}

/*
 * Stop and delete the channel's switch timer.
 */
void consumer_timer_switch_stop(struct lttng_consumer_channel *channel)
{
	int ret;

	LTTNG_ASSERT(channel);

	ret = consumer_channel_timer_stop(&channel->switch_timer, LTTNG_CONSUMER_SIG_SWITCH);
	if (ret == -1) {
		ERR("Failed to stop switch timer");
	}

	channel->metadata_switch_timer_task.reset();
}

/* Start the channel's periodic "live mode" management task. */
void consumer_timer_live_start(struct lttng_consumer_channel *channel,
			       unsigned int live_timer_interval_us,
			       lttng::scheduling::scheduler& scheduler)
{
	LTTNG_ASSERT(channel);
	LTTNG_ASSERT(channel->key);
	LTTNG_ASSERT(!channel->is_deleted);

	if (live_timer_interval_us == 0) {
		/* No creation needed; not an error. */
		return;
	}

	try {
		channel->live_timer_task = std::make_shared<lttng::consumer::live_timer_task>(
			std::chrono::microseconds(live_timer_interval_us), *channel);

		scheduler.schedule(channel->live_timer_task,
				   std::chrono::steady_clock::now() +
					   std::chrono::microseconds(live_timer_interval_us));
	} catch (const std::bad_alloc& e) {
		ERR_FMT("Failed to allocate memory for live timer task: {}: channel_name=`{}`, key={}, session_id={}",
			e.what(),
			channel->name,
			channel->key,
			channel->session_id);
		return;
	}
}

/* Stop the channel's "live mode" management task. */
void consumer_timer_live_stop(struct lttng_consumer_channel *channel)
{
	LTTNG_ASSERT(channel);
	if (!channel->live_timer_task) {
		return;
	}

	/* Cancel the live timer task if it is scheduled. */
	channel->live_timer_task->cancel();
	channel->live_timer_task.reset();
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

	LTTNG_ASSERT(channel);
	LTTNG_ASSERT(channel->key);
	LTTNG_ASSERT(!channel->is_deleted);
	LTTNG_ASSERT(!channel->monitor_timer_task);

	if (monitor_timer_interval_us == 0) {
		/* No creation needed; not an error. */
		return 0;
	}

	try {
		channel->monitor_timer_task = std::make_shared<lttng::consumer::monitor_timer_task>(
			std::chrono::microseconds(monitor_timer_interval_us),
			*channel,
			consumer_timer_thread_get_channel_monitor_pipe());
	} catch (const std::bad_alloc& e) {
		ERR_FMT("Failed to allocate memory for live timer task: {}: channel_name=`{}`",
			e.what(),
			channel->name);
		return -1;
	}

	ret = consumer_channel_timer_start(&channel->monitor_timer,
					   channel,
					   monitor_timer_interval_us,
					   LTTNG_CONSUMER_SIG_MONITOR);
	if (ret) {
		ERR_FMT("Failed to start monitor timer: channel_name=`{}`", channel->name);
		channel->monitor_timer_task.reset();
	}

	return ret;
}

/*
 * Stop and delete the channel's monitoring timer.
 */
int consumer_timer_monitor_stop(struct lttng_consumer_channel *channel)
{
	int ret;

	LTTNG_ASSERT(channel);
	LTTNG_ASSERT(channel->monitor_timer_task);

	ret = consumer_channel_timer_stop(&channel->monitor_timer, LTTNG_CONSUMER_SIG_MONITOR);
	if (ret == -1) {
		ERR("Failed to stop monitor timer");
		goto end;
	}

	channel->monitor_timer_task.reset();
end:
	return ret;
}

/*
 * Block the RT signals for the entire process. It must be called from the
 * consumer main before creating the threads
 */
int consumer_signal_init()
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

int consumer_timer_thread_get_channel_monitor_pipe()
{
	return uatomic_read(&the_channel_monitor_pipe);
}

int consumer_timer_thread_set_channel_monitor_pipe(int fd)
{
	int ret;

	ret = uatomic_cmpxchg(&the_channel_monitor_pipe, -1, fd);
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
 * LTTNG_CONSUMER_SIG_TEARDOWN, and LTTNG_CONSUMER_SIG_MONITOR,
 * LTTNG_CONSUMER_SIG_EXIT.
 */
void *consumer_timer_thread(void *data [[maybe_unused]])
{
	int signr;
	sigset_t mask;
	siginfo_t info;

	rcu_register_thread();

	health_register(health_consumerd, HEALTH_CONSUMERD_TYPE_METADATA_TIMER);

	if (testpoint(consumerd_thread_metadata_timer)) {
		goto error_testpoint;
	}

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
		} else if (signr == LTTNG_CONSUMER_SIG_SWITCH) {
			auto *channel = (lttng_consumer_channel *) info.si_value.sival_ptr;

			channel->metadata_switch_timer_task->run(std::chrono::steady_clock::now());
		} else if (signr == LTTNG_CONSUMER_SIG_TEARDOWN) {
			cmm_smp_mb();
			CMM_STORE_SHARED(timer_signal.qs_done, 1);
			cmm_smp_mb();
			DBG("Signal timer metadata thread teardown");
		} else if (signr == LTTNG_CONSUMER_SIG_MONITOR) {
			auto *channel = (lttng_consumer_channel *) info.si_value.sival_ptr;

			channel->monitor_timer_task->run(std::chrono::steady_clock::now());
		} else if (signr == LTTNG_CONSUMER_SIG_EXIT) {
			LTTNG_ASSERT(CMM_LOAD_SHARED(consumer_quit));
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
	return nullptr;
}
