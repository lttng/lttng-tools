#include <stdio.h>
#include <poll.h>
#include <signal.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <sys/select.h>
#include <sys/epoll.h>
#include <popt.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <limits.h>
#include <pthread.h>
#include <sys/mman.h>
#include <common/compat/time.h>

#define BUF_SIZE 256
#define NB_FD 1
#define MAX_FDS 2047
#define NR_ITER 1000 /* for stress-tests */

#define MIN_NR_FDS 5 /* the minimum number of open FDs required for the test to run */
#define BIG_SELECT_FD 1022

#define MSEC_PER_USEC 1000
#define MSEC_PER_NSEC (MSEC_PER_USEC * 1000)

static int timeout; /* seconds, -1 to disable */
volatile static int stop_thread;
static int wait_fd;

struct ppoll_thread_data {
	struct pollfd *ufds;
	int value;
};

void test_select_big(void)
{
	fd_set rfds, wfds, exfds;
	struct timeval tv;
	int ret;
	int fd2;
	char buf[BUF_SIZE];

	FD_ZERO(&rfds);
	FD_ZERO(&wfds);
	FD_ZERO(&exfds);

	fd2 = dup2(wait_fd, BIG_SELECT_FD);
	if (fd2 < 0) {
		perror("dup2");
		goto end;
	}
	FD_SET(fd2, &rfds);

	tv.tv_sec = 0;
	tv.tv_usec = timeout * MSEC_PER_USEC;

	if (timeout > 0) {
		ret = select(fd2 + 1, &rfds, &wfds, &exfds, &tv);
	} else {
		ret = select(fd2 + 1, &rfds, &wfds, &exfds, NULL);
	}

	if (ret == -1) {
		perror("select()");
	} else if (ret) {
		printf("# [select] data available\n");
		ret = read(wait_fd, buf, BUF_SIZE);
		if (ret < 0) {
			perror("[select] read");
		}
	} else {
		printf("# [select] timeout\n");
	}

	ret = close(BIG_SELECT_FD);
	if (ret) {
		perror("close");
	}

end:
	return;
}

void test_pselect(void)
{
	fd_set rfds;
	struct timespec tv;
	int ret;
	char buf[BUF_SIZE];

	FD_ZERO(&rfds);
	FD_SET(wait_fd, &rfds);

	tv.tv_sec = 0;
	tv.tv_nsec = timeout * MSEC_PER_NSEC;

	if (timeout > 0) {
		ret = pselect(1, &rfds, NULL, NULL, &tv, NULL);
	} else {
		ret = pselect(1, &rfds, NULL, NULL, NULL, NULL);
	}

	if (ret == -1) {
		perror("pselect()");
	} else if (ret) {
		printf("# [pselect] data available\n");
		ret = read(wait_fd, buf, BUF_SIZE);
		if (ret < 0) {
			perror("[pselect] read");
		}
	} else {
		printf("# [pselect] timeout\n");
	}

}

void test_select(void)
{
	fd_set rfds;
	struct timeval tv;
	int ret;
	char buf[BUF_SIZE];

	FD_ZERO(&rfds);
	FD_SET(wait_fd, &rfds);

	tv.tv_sec = 0;
	tv.tv_usec = timeout * MSEC_PER_USEC;

	if (timeout > 0) {
		ret = select(1, &rfds, NULL, NULL, &tv);
	} else {
		ret = select(1, &rfds, NULL, NULL, NULL);
	}

	if (ret == -1) {
		perror("select()");
	} else if (ret) {
		printf("# [select] data available\n");
		ret = read(wait_fd, buf, BUF_SIZE);
		if (ret < 0) {
			perror("[select] read");
		}
	} else {
		printf("# [select] timeout\n");
	}

}

void test_poll(void)
{
	struct pollfd ufds[NB_FD];
	char buf[BUF_SIZE];
	int ret;

	ufds[0].fd = wait_fd;
	ufds[0].events = POLLIN|POLLPRI;

	ret = poll(ufds, 1, timeout);

	if (ret < 0) {
		perror("poll");
	} else if (ret > 0) {
		printf("# [poll] data available\n");
		ret = read(wait_fd, buf, BUF_SIZE);
		if (ret < 0) {
			perror("[poll] read");
		}
	} else {
		printf("# [poll] timeout\n");
	}
}

void test_ppoll(void)
{
	struct pollfd ufds[NB_FD];
	char buf[BUF_SIZE];
	int ret;
	struct timespec ts;

	ufds[0].fd = wait_fd;
	ufds[0].events = POLLIN|POLLPRI;

	if (timeout > 0) {
		ts.tv_sec = 0;
		ts.tv_nsec = timeout * MSEC_PER_NSEC;
		ret = ppoll(ufds, 1, &ts, NULL);
	} else {
		ret = ppoll(ufds, 1, NULL, NULL);
	}


	if (ret < 0) {
		perror("ppoll");
	} else if (ret > 0) {
		printf("# [ppoll] data available\n");
		ret = read(wait_fd, buf, BUF_SIZE);
		if (ret < 0) {
			perror("[ppoll] read");
		}
	} else {
		printf("# [ppoll] timeout\n");
	}
}

void test_ppoll_big(void)
{
	struct pollfd ufds[MAX_FDS];
	char buf[BUF_SIZE];
	int ret, i, fds[MAX_FDS];

	for (i = 0; i < MAX_FDS; i++) {
		fds[i] = dup(wait_fd);
		if (fds[i] < 0) {
			perror("dup");
		}
		ufds[i].fd = fds[i];
		ufds[i].events = POLLIN|POLLPRI;
	}

	ret = ppoll(ufds, MAX_FDS, NULL, NULL);

	if (ret < 0) {
		perror("ppoll");
	} else if (ret > 0) {
		printf("# [ppoll] data available\n");
		ret = read(wait_fd, buf, BUF_SIZE);
		if (ret < 0) {
			perror("[ppoll] read");
		}
	} else {
		printf("# [ppoll] timeout\n");
	}

	for (i = 0; i < MAX_FDS; i++) {
		ret = close(fds[i]);
		if (ret != 0) {
			perror("close");
		}
	}

	return;
}

void test_epoll(void)
{
	int ret, epollfd;
	char buf[BUF_SIZE];
	struct epoll_event epoll_event;

	epollfd = epoll_create(NB_FD);
	if (epollfd < 0) {
		perror("[epoll] create");
		goto end;
	}

	epoll_event.events = EPOLLIN | EPOLLPRI | EPOLLET;
	epoll_event.data.fd = wait_fd;
	ret = epoll_ctl(epollfd, EPOLL_CTL_ADD, wait_fd, &epoll_event);
	if (ret < 0) {
		perror("[epoll] add");
		goto end;
	}

	if (timeout > 0) {
		ret = epoll_wait(epollfd, &epoll_event, 1, timeout);
	} else {
		ret = epoll_wait(epollfd, &epoll_event, 1, -1);
	}

	if (ret == 1) {
		printf("# [epoll] data available\n");
		ret = read(wait_fd, buf, BUF_SIZE);
		if (ret < 0) {
			perror("[epoll] read");
		}
	} else if (ret == 0) {
		printf("# [epoll] timeout\n");
	} else {
		perror("epoll_wait");
	}

end:
	return;
}

void test_pepoll(void)
{
	int ret, epollfd;
	char buf[BUF_SIZE];
	struct epoll_event epoll_event;

	epollfd = epoll_create(NB_FD);
	if (epollfd < 0) {
		perror("[eppoll] create");
		goto end;
	}

	epoll_event.events = EPOLLIN | EPOLLPRI | EPOLLET;
	epoll_event.data.fd = wait_fd;
	ret = epoll_ctl(epollfd, EPOLL_CTL_ADD, wait_fd, &epoll_event);
	if (ret < 0) {
		perror("[eppoll] add");
		goto end;
	}

	if (timeout > 0) {
		ret = epoll_pwait(epollfd, &epoll_event, 1, timeout, NULL);
	} else {
		ret = epoll_pwait(epollfd, &epoll_event, 1, -1, NULL);
	}

	if (ret == 1) {
		printf("# [eppoll] data available\n");
		ret = read(wait_fd, buf, BUF_SIZE);
		if (ret < 0) {
			perror("[eppoll] read");
		}
	} else if (ret == 0) {
		printf("# [eppoll] timeout\n");
	} else {
		perror("epoll_pwait");
	}

end:
	return;
}

void run_working_cases(void)
{
	int ret;
	int pipe_fds[2];

	if (timeout > 0) {
		/*
		 * We need an input pipe for some cases and stdin might
		 * have random data, so we create a dummy pipe for this
		 * test to make sure we are running under clean conditions.
		 */
		ret = pipe(pipe_fds);
		if (ret != 0) {
			perror("pipe");
			goto end;
		}
		wait_fd = pipe_fds[0];
	}
	test_select();
	test_pselect();
	test_select_big();
	test_poll();
	test_ppoll();
	test_epoll();
	test_pepoll();

	if (timeout > 0) {
		ret = close(pipe_fds[0]);
		if (ret) {
			perror("close");
		}
		ret = close(pipe_fds[1]);
		if (ret) {
			perror("close");
		}
	}

end:
	return;
}

/*
 * Ask for 100 FDs in a buffer for allocated for only 1 FD, should
 * segfault (eventually with a "*** stack smashing detected ***" message).
 * The event should contain an array of 100 FDs filled with garbage.
 */
void ppoll_fds_buffer_overflow(void)
{
	struct pollfd ufds[NB_FD];
	char buf[BUF_SIZE];
	int ret;

	ufds[0].fd = wait_fd;
	ufds[0].events = POLLIN|POLLPRI;

	ret = syscall(SYS_ppoll, ufds, 100, NULL, NULL);

	if (ret < 0) {
		perror("ppoll");
	} else if (ret > 0) {
		printf("# [ppoll] data available\n");
		ret = read(wait_fd, buf, BUF_SIZE);
		if (ret < 0) {
			perror("[ppoll] read");
		}
	} else {
		printf("# [ppoll] timeout\n");
	}

	return;
}

/*
 * Ask for ULONG_MAX FDs in a buffer for allocated for only 1 FD, should
 * cleanly fail with a "Invalid argument".
 * The event should contain an empty array of FDs and overflow = 1.
 */
void ppoll_fds_ulong_max(void)
{
	struct pollfd ufds[NB_FD];
	char buf[BUF_SIZE];
	int ret;

	ufds[0].fd = wait_fd;
	ufds[0].events = POLLIN|POLLPRI;

	ret = syscall(SYS_ppoll, ufds, ULONG_MAX, NULL, NULL);

	if (ret < 0) {
		perror("# ppoll");
	} else if (ret > 0) {
		printf("# [ppoll] data available\n");
		ret = read(wait_fd, buf, BUF_SIZE);
		if (ret < 0) {
			perror("[ppoll] read");
		}
	} else {
		printf("# [ppoll] timeout\n");
	}

	return;
}

/*
 * Pass an invalid file descriptor to pselect6(). The syscall should return
 * -EBADF. The recorded event should contain a "ret = -EBADF (-9)".
 */
void pselect_invalid_fd(void)
{
	fd_set rfds;
	int ret;
	int fd;
	char buf[BUF_SIZE];

	/*
	 * Open a file, close it and use the closed FD in the pselect6 call.
	 */

	fd = open("/dev/null", O_RDONLY);
	if (fd == -1) {
		perror("open");
		goto error;
	}

	ret = close(fd);
	if (ret == -1) {
		perror("close");
		goto error;
	}

	FD_ZERO(&rfds);
	FD_SET(fd, &rfds);

	ret = syscall(SYS_pselect6, fd + 1, &rfds, NULL, NULL, NULL, NULL);
	if (ret == -1) {
		perror("# pselect()");
	} else if (ret) {
		printf("# [pselect] data available\n");
		ret = read(wait_fd, buf, BUF_SIZE);
		if (ret < 0) {
			perror("[pselect] read");
		}
	} else {
		printf("# [pselect] timeout\n");
	}
error:
	return;
}

/*
 * Invalid pointer as writefds, should output a ppoll event
 * with 0 FDs.
 */
void pselect_invalid_pointer(void)
{
	fd_set rfds;
	int ret;
	char buf[BUF_SIZE];
	void *invalid = (void *) 0x42;

	FD_ZERO(&rfds);
	FD_SET(wait_fd, &rfds);

	ret = syscall(SYS_pselect6, 1, &rfds, (fd_set *) invalid, NULL, NULL,
			NULL);

	if (ret == -1) {
		perror("# pselect()");
	} else if (ret) {
		printf("# [pselect] data available\n");
		ret = read(wait_fd, buf, BUF_SIZE);
		if (ret < 0) {
			perror("[pselect] read");
		}
	} else {
		printf("# [pselect] timeout\n");
	}

}

/*
 * Pass an invalid pointer to epoll_pwait, should fail with
 * "Bad address", the event returns 0 FDs.
 */
void epoll_pwait_invalid_pointer(void)
{
	int ret, epollfd;
	char buf[BUF_SIZE];
	struct epoll_event epoll_event;
	void *invalid = (void *) 0x42;

	epollfd = epoll_create(NB_FD);
	if (epollfd < 0) {
		perror("[eppoll] create");
		goto end;
	}

	epoll_event.events = EPOLLIN | EPOLLPRI | EPOLLET;
	epoll_event.data.fd = wait_fd;
	ret = epoll_ctl(epollfd, EPOLL_CTL_ADD, wait_fd, &epoll_event);
	if (ret < 0) {
		perror("[eppoll] add");
		goto end;
	}

	ret = syscall(SYS_epoll_pwait, epollfd,
			(struct epoll_event *) invalid, 1, -1, NULL);

	if (ret == 1) {
		printf("# [eppoll] data available\n");
		ret = read(wait_fd, buf, BUF_SIZE);
		if (ret < 0) {
			perror("[eppoll] read");
		}
	} else if (ret == 0) {
		printf("# [eppoll] timeout\n");
	} else {
		perror("# epoll_pwait");
	}

end:
	return;
}

/*
 * Set maxevents to INT_MAX, should output "Invalid argument"
 * The event should return an empty array.
 */
void epoll_pwait_int_max(void)
{
	int ret, epollfd;
	char buf[BUF_SIZE];
	struct epoll_event epoll_event;

	epollfd = epoll_create(NB_FD);
	if (epollfd < 0) {
		perror("[eppoll] create");
		goto end;
	}

	epoll_event.events = EPOLLIN | EPOLLPRI | EPOLLET;
	epoll_event.data.fd = wait_fd;
	ret = epoll_ctl(epollfd, EPOLL_CTL_ADD, wait_fd, &epoll_event);
	if (ret < 0) {
		perror("[eppoll] add");
		goto end;
	}

	ret = syscall(SYS_epoll_pwait, epollfd, &epoll_event, INT_MAX, -1,
			NULL);

	if (ret == 1) {
		printf("# [eppoll] data available\n");
		ret = read(wait_fd, buf, BUF_SIZE);
		if (ret < 0) {
			perror("[eppoll] read");
		}
	} else if (ret == 0) {
		printf("# [eppoll] timeout\n");
	} else {
		perror("# epoll_pwait");
	}

end:
	return;
}

void *ppoll_writer(void *arg)
{
	struct ppoll_thread_data *data = (struct ppoll_thread_data *) arg;

	while (!stop_thread) {
		memset(data->ufds, data->value,
				MAX_FDS * sizeof(struct pollfd));
		usleep(100);
	}

	return NULL;
}

void do_ppoll(int *fds, struct pollfd *ufds)
{
	int i, ret;
	struct timespec ts;
	char buf[BUF_SIZE];

	ts.tv_sec = 0;
	ts.tv_nsec = 1 * MSEC_PER_NSEC;

	for (i = 0; i < MAX_FDS; i++) {
		ufds[i].fd = fds[i];
		ufds[i].events = POLLIN|POLLPRI;
	}

	ret = ppoll(ufds, MAX_FDS, &ts, NULL);

	if (ret < 0) {
		perror("ppoll");
	} else if (ret > 0) {
		printf("# [ppoll] data available\n");
		ret = read(wait_fd, buf, BUF_SIZE);
		if (ret < 0) {
			perror("[ppoll] read");
		}
	} else {
		printf("# [ppoll] timeout\n");
	}
}

void stress_ppoll(int *fds, int value)
{
	pthread_t writer;
	int iter, ret;
	struct ppoll_thread_data thread_data;
	struct pollfd ufds[MAX_FDS];

	thread_data.ufds = ufds;
	thread_data.value = value;

	stop_thread = 0;
	ret = pthread_create(&writer, NULL, &ppoll_writer, (void *) &thread_data);
	if (ret != 0) {
		fprintf(stderr, "[error] pthread_create\n");
		goto end;
	}
	for (iter = 0; iter < NR_ITER; iter++) {
		do_ppoll(fds, ufds);
	}
	stop_thread = 1;
	ret = pthread_join(writer, NULL);
	if (ret) {
		fprintf(stderr, "[error] pthread_join\n");
		goto end;
	}
end:
	return;
}

/*
 * 3 rounds of NR_ITER iterations with concurrent updates of the pollfd
 * structure:
 *   - memset to 0
 *   - memset to 1
 *   - memset to INT_MAX
 * Waits for input, but also set a timeout in case the input FD is overwritten
 * before entering in the syscall. We use MAX_FDS FDs (dup of stdin), so the
 * resulting trace is big (20MB).
 *
 * ppoll should work as expected and the trace should be readable at the end.
 */
void ppoll_concurrent_write(void)
{
	int i, ret, fds[MAX_FDS];

	for (i = 0; i < MAX_FDS; i++) {
		fds[i] = dup(wait_fd);
		if (fds[i] < 0) {
			perror("dup");
		}
	}

	stress_ppoll(fds, 0);
	stress_ppoll(fds, 1);
	stress_ppoll(fds, INT_MAX);

	for (i = 0; i < MAX_FDS; i++) {
		ret = close(fds[i]);
		if (ret != 0) {
			perror("close");
		}
	}

	return;
}

void *epoll_pwait_writer(void *addr)
{
	srand(time(NULL));

	while (!stop_thread) {
		usleep(rand() % 30);
		munmap(addr, MAX_FDS * sizeof(struct epoll_event));
	}

	return NULL;
}

/*
 * epoll_pwait on MAX_FDS fds while a concurrent thread munmaps the
 * buffer allocated for the returned data. This should randomly segfault.
 * The trace should be readable and no kernel OOPS should occur.
 */
void epoll_pwait_concurrent_munmap(void)
{
	int ret, epollfd, i, fds[MAX_FDS];
	char buf[BUF_SIZE];
	struct epoll_event *epoll_event;
	pthread_t writer;

	epollfd = epoll_create(MAX_FDS);
	if (epollfd < 0) {
		perror("[eppoll] create");
		goto end;
	}

	epoll_event = mmap(NULL, MAX_FDS * sizeof(struct epoll_event),
			PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS,
			-1, 0);
	if (epoll_event == MAP_FAILED) {
		perror("mmap");
		goto end;
	}

	for (i = 0; i < MAX_FDS; i++) {
		fds[i] = dup(wait_fd);
		if (fds[i] < 0) {
			perror("dup");
		}
		epoll_event[i].events = EPOLLIN | EPOLLPRI | EPOLLET;
		epoll_event[i].data.fd = fds[i];
		ret = epoll_ctl(epollfd, EPOLL_CTL_ADD, fds[i], epoll_event);
		if (ret < 0) {
			perror("[eppoll] add");
			goto end_unmap;
		}
	}
	stop_thread = 0;
	ret = pthread_create(&writer, NULL, &epoll_pwait_writer,
			(void *) epoll_event);
	if (ret != 0) {
		fprintf(stderr, "[error] pthread_create\n");
		goto end_unmap;
	}

	ret = epoll_pwait(epollfd, epoll_event, 1, 1, NULL);

	if (ret == 1) {
		printf("# [eppoll] data available\n");
		ret = read(wait_fd, buf, BUF_SIZE);
		if (ret < 0) {
			perror("[eppoll] read");
		}
	} else if (ret == 0) {
		printf("# [eppoll] timeout\n");
	} else {
		perror("# epoll_pwait");
	}

	stop_thread = 1;
	ret = pthread_join(writer, NULL);
	if (ret) {
		fprintf(stderr, "[error] pthread_join\n");
		goto end_unmap;
	}
end_unmap:
	for (i = 0; i < MAX_FDS; i++) {
		ret = close(fds[i]);
		if (ret != 0) {
			perror("close");
		}
	}

	ret = munmap(epoll_event, MAX_FDS * sizeof(struct epoll_event));
	if (ret != 0) {
		perror("munmap");
	}

end:
	return;
}

void usage(poptContext optCon, int exitcode, char *error, char *addl)
{
	poptPrintUsage(optCon, stderr, 0);
	if (error) {
		fprintf(stderr, "%s: %s\n", error, addl);
	}
	exit(exitcode);
}

void print_list(void)
{
	fprintf(stderr, "Test list (-t X):\n");
	fprintf(stderr, "\t1: Working cases for select, pselect6, poll, ppoll "
			"and epoll, waiting for input\n");
	fprintf(stderr, "\t2: Timeout cases (1ms) for select, pselect6, poll, "
			"ppoll and epoll\n");
	fprintf(stderr, "\t3: pselect with an invalid fd\n");
	fprintf(stderr, "\t4: ppoll with %d FDs\n", MAX_FDS);
	fprintf(stderr, "\t5: ppoll buffer overflow, should segfault, waits "
			"for input\n");
	fprintf(stderr, "\t6: pselect with an invalid pointer, waits for "
			"input\n");
	fprintf(stderr, "\t7: ppoll with ulong_max fds, waits for input\n");
	fprintf(stderr, "\t8: epoll_pwait with an invalid pointer, waits for "
			"input\n");
	fprintf(stderr, "\t9: epoll_pwait with maxevents set to INT_MAX, "
			"waits for input\n");
	fprintf(stderr, "\t10: ppoll with concurrent updates of the structure "
			"from user-space, stress test (3000 iterations), "
			"waits for input + timeout 1ms\n");
	fprintf(stderr, "\t11: epoll_pwait with concurrent munmap of the buffer "
			"from user-space, should randomly segfault, run "
			"multiple times, waits for input + timeout 1ms\n");
}

int main(int argc, const char **argv)
{
	int c, ret, test = -1;
	poptContext optCon;
	struct rlimit open_lim;

	struct poptOption optionsTable[] = {
		{ "test", 't', POPT_ARG_INT, &test, 0,
			"Test to run", NULL },
		{ "list", 'l', 0, 0, 'l',
			"List of tests (-t X)", NULL },
		POPT_AUTOHELP
		{ NULL, 0, 0, NULL, 0 }
	};

	optCon = poptGetContext(NULL, argc, argv, optionsTable, 0);

	if (argc < 2) {
		poptPrintUsage(optCon, stderr, 0);
		ret = -1;
		goto end;
	}

	ret = 0;

	while ((c = poptGetNextOpt(optCon)) >= 0) {
		switch(c) {
		case 'l':
			print_list();
			goto end;
		}
	}

	open_lim.rlim_cur = MAX_FDS + MIN_NR_FDS;
	open_lim.rlim_max = MAX_FDS + MIN_NR_FDS;

	ret = setrlimit(RLIMIT_NOFILE, &open_lim);
	if (ret < 0) {
		perror("setrlimit");
		goto end;
	}

	/*
	 * Some tests might segfault, but we need the getpid() to be output
	 * for the validation, disabling the buffering on stdout works.
	 */
	setbuf(stdout, NULL);
	printf("%d\n", getpid());

	wait_fd = STDIN_FILENO;

	switch(test) {
	case 1:
		timeout = -1;
		run_working_cases();
		break;
	case 2:
		timeout = 1;
		run_working_cases();
		break;
	case 3:
		pselect_invalid_fd();
		break;
	case 4:
		test_ppoll_big();
		break;
	case 5:
		ppoll_fds_buffer_overflow();
		break;
	case 6:
		pselect_invalid_pointer();
		break;
	case 7:
		ppoll_fds_ulong_max();
		break;
	case 8:
		epoll_pwait_invalid_pointer();
		break;
	case 9:
		epoll_pwait_int_max();
		break;
	case 10:
		ppoll_concurrent_write();
		break;
	case 11:
		epoll_pwait_concurrent_munmap();
		break;
	default:
		poptPrintUsage(optCon, stderr, 0);
		ret = -1;
		break;
	}

end:
	poptFreeContext(optCon);
	return ret;
}
