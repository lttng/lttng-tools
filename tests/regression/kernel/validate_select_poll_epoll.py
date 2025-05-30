#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2016 Julien Desfossez <jdesfossez@efficios.com>
#
# SPDX-License-Identifier: GPL-2.0-only
#

import argparse
import platform
import pprint
import sys
import time
import json

from collections import defaultdict

try:
    import bt2
except ImportError:
    # quick fix for debian-based distros
    sys.path.append(
        "/usr/local/lib/python%d.%d/site-packages"
        % (sys.version_info.major, sys.version_info.minor)
    )
    import bt2

NSEC_PER_SEC = 1000000000


class TraceParser:
    def __init__(self, trace_msg_iter, pid):
        self.trace = trace_msg_iter
        self.pid = pid

        # This dictionnary holds the results of each testcases of a test.
        # Its layout is the following:
        #       self.expect={
        #                       'event_name_1': {'check_1': 0, 'check_2: 1},
        #                       'event_name_2': {'check_1': 1}
        #                   }
        # Each test classes checks the payload of different events. Each of
        # those checks are stored in a event_name specific dictionnary in this
        # data structure.
        self.expect = defaultdict(lambda: defaultdict(int))

        # This dictionnary holds the value recorded in the trace that are
        # tested. Its content is use to print the values that caused a test to
        # fail.
        self.recorded_values = {}

    def ns_to_hour_nsec(self, ns):
        d = time.localtime(ns / NSEC_PER_SEC)
        return "%02d:%02d:%02d.%09d" % (
            d.tm_hour,
            d.tm_min,
            d.tm_sec,
            ns % NSEC_PER_SEC,
        )

    def parse(self):
        # iterate over all the events
        for msg in self.trace:
            if type(msg) is not bt2._EventMessageConst:
                continue

            if self.pid is not None and msg.event["pid"] != self.pid:
                continue

            method_name = "handle_%s" % msg.event.name.replace(":", "_").replace(
                "+", "_"
            )
            # call the function to handle each event individually
            if hasattr(TraceParser, method_name):
                func = getattr(TraceParser, method_name)
                func(self, msg.event)

        ret = 0
        # For each event of the test case, check all entries for failed
        for event_name, event_results in self.expect.items():
            for val in event_results.keys():
                if self.expect[event_name][val] == 0:
                    print("%s not validated" % val)
                    print("Values of the local variables of this test:")
                    # using pprint for pretty printing the dictionnary
                    pprint.pprint(self.recorded_values[event_name])
                    ret = 1

        return ret

    # epoll_ctl
    def handle_compat_syscall_entry_epoll_ctl(self, event):
        self.epoll_ctl_entry(event)

    def handle_compat_syscall_exit_epoll_ctl(self, event):
        self.epoll_ctl_exit(event)

    def handle_syscall_entry_epoll_ctl(self, event):
        self.epoll_ctl_entry(event)

    def handle_syscall_exit_epoll_ctl(self, event):
        self.epoll_ctl_exit(event)

    def epoll_ctl_entry(self, event):
        pass

    def epoll_ctl_exit(self, event):
        pass

    # epoll_wait + epoll_pwait
    def handle_compat_syscall_entry_epoll_wait(self, event):
        self.epoll_wait_entry(event)

    def handle_compat_syscall_exit_epoll_wait(self, event):
        self.epoll_wait_exit(event)

    def handle_syscall_entry_epoll_wait(self, event):
        self.epoll_wait_entry(event)

    def handle_syscall_exit_epoll_wait(self, event):
        self.epoll_wait_exit(event)

    def handle_compat_syscall_entry_epoll_pwait(self, event):
        self.epoll_pwait_entry(event)

    def handle_compat_syscall_exit_epoll_pwait(self, event):
        self.epoll_pwait_exit(event)

    def handle_syscall_entry_epoll_pwait(self, event):
        self.epoll_pwait_entry(event)

    def handle_syscall_exit_epoll_pwait(self, event):
        self.epoll_pwait_exit(event)

    def epoll_wait_entry(self, event):
        pass

    def epoll_wait_exit(self, event):
        pass

    def epoll_pwait_entry(self, event):
        self.epoll_wait_entry(event)

    def epoll_pwait_exit(self, event):
        self.epoll_wait_exit(event)

    ## poll + ppoll
    def handle_compat_syscall_entry_poll(self, event):
        self.poll_entry(event)

    def handle_compat_syscall_exit_poll(self, event):
        self.poll_exit(event)

    def handle_syscall_entry_poll(self, event):
        self.poll_entry(event)

    def handle_syscall_exit_poll(self, event):
        self.poll_exit(event)

    def handle_compat_syscall_entry_ppoll(self, event):
        self.poll_entry(event)

    def handle_compat_syscall_exit_ppoll(self, event):
        self.poll_exit(event)

    def handle_syscall_entry_ppoll(self, event):
        self.poll_entry(event)

    def handle_syscall_exit_ppoll(self, event):
        self.poll_exit(event)

    def poll_entry(self, event):
        pass

    def poll_exit(self, event):
        pass

    # epoll_create
    def handle_compat_syscall_entry_epoll_create1(self, event):
        self.epoll_create_entry(event)

    def handle_compat_syscall_exit_epoll_create1(self, event):
        self.epoll_create_exit(event)

    def handle_compat_syscall_entry_epoll_create(self, event):
        self.epoll_create_entry(event)

    def handle_compat_syscall_exit_epoll_create(self, event):
        self.epoll_create_exit(event)

    def handle_syscall_entry_epoll_create1(self, event):
        self.epoll_create_entry(event)

    def handle_syscall_exit_epoll_create1(self, event):
        self.epoll_create_exit(event)

    def handle_syscall_entry_epoll_create(self, event):
        self.epoll_create_entry(event)

    def handle_syscall_exit_epoll_create(self, event):
        self.epoll_create_exit(event)

    def epoll_create_entry(self, event):
        pass

    def epoll_create_exit(self, event):
        pass

    # select + pselect6
    def handle_syscall_entry_pselect6(self, event):
        self.select_entry(event)

    def handle_syscall_exit_pselect6(self, event):
        self.select_exit(event)

    def handle_compat_syscall_entry_pselect6(self, event):
        self.select_entry(event)

    def handle_compat_syscall_exit_pselect6(self, event):
        self.select_exit(event)

    def handle_syscall_entry_select(self, event):
        self.select_entry(event)

    def handle_syscall_exit_select(self, event):
        self.select_exit(event)

    def handle_compat_syscall_entry_select(self, event):
        self.select_entry(event)

    def handle_compat_syscall_exit_select(self, event):
        self.select_exit(event)

    def select_entry(self, event):
        pass

    def select_exit(self, event):
        pass


class WorkingCases(TraceParser):
    def __init__(self, trace, validation_args):
        super().__init__(trace, validation_args["pid"])

        # Values expected in the trace
        self.epoll_wait_fd = validation_args["epoll_wait_fd"]
        self.epoll_pwait_fd = validation_args["epoll_pwait_fd"]

        self.expect["select_entry"]["select_in_fd0"] = 0
        self.expect["select_entry"]["select_in_fd1023"] = 0
        self.expect["select_exit"]["select_out_fd0"] = 0
        self.expect["select_exit"]["select_out_fd1023"] = 0
        self.expect["poll_entry"]["poll_in_nfds1"] = 0
        self.expect["poll_exit"]["poll_out_nfds1"] = 0
        self.expect["epoll_ctl_entry"]["epoll_ctl_in_add"] = 0
        self.expect["epoll_ctl_exit"]["epoll_ctl_out_ok"] = 0
        self.expect["epoll_pwait_entry"]["epoll_pwait_in_ok"] = 0
        self.expect["epoll_pwait_exit"]["epoll_pwait_out_fd0"] = 0

        # epoll_wait does not exist linux arm64 and riscv64
        if platform.machine() not in ["aarch64", "riscv64"]:
            self.expect["epoll_wait_entry"]["epoll_wait_in_ok"] = 0
            self.expect["epoll_wait_exit"]["epoll_wait_out_fd0"] = 0

    def select_entry(self, event):
        n = event["n"]
        overflow = event["overflow"]
        readfd_0 = event["readfds"][0]

        # check that the FD 0 is actually set in the readfds
        if n == 1 and readfd_0 == 1:
            self.expect["select_entry"]["select_in_fd0"] = 1
        if n == 1023:
            readfd_127 = event["readfds"][127]
            writefd_127 = event["writefds"][127]
            exceptfd_127 = event["exceptfds"][127]

            # check that the FD 1023 is actually set in the readfds
            if (
                readfd_127 == 0x40
                and writefd_127 == 0
                and exceptfd_127 == 0
                and overflow == 0
            ):
                self.expect["select_entry"]["select_in_fd1023"] = 1

        # Save values of local variables to print in case of test failure
        self.recorded_values["select_entry"] = locals()

    def select_exit(self, event):
        ret = event["ret"]
        tvp = event["tvp"]
        overflow = event["overflow"]
        _readfds_length = event["_readfds_length"]

        if ret == 1:
            # check that the FD 0 is actually set in the readfds
            readfd_0 = event["readfds"][0]

            if readfd_0 == 1:
                self.expect["select_exit"]["select_out_fd0"] = 1
            # check that the FD 1023 is actually set in the readfds
            if _readfds_length == 128:
                readfd_127 = event["readfds"][127]
                writefd_127 = event["writefds"][127]
                exceptfd_127 = event["exceptfds"][127]
                if (
                    readfd_127 == 0x40
                    and writefd_127 == 0
                    and exceptfd_127 == 0
                    and tvp == 0
                ):
                    self.expect["select_exit"]["select_out_fd1023"] = 1

        # Save values of local variables to print in case of test failure
        self.recorded_values["select_exit"] = locals()

    def poll_entry(self, event):
        nfds = event["nfds"]
        fds_length = event["fds_length"]
        overflow = event["overflow"]

        # check that only one FD is set, that it has the POLLIN flag and that
        # the raw value matches the events bit field.
        if nfds == 1 and fds_length == 1:
            fd_0 = event["fds"][0]
            if (
                fd_0["raw_events"] == 0x3
                and fd_0["events"]["POLLIN"] == 1
                and fd_0["events"]["padding"] == 0
            ):
                self.expect["poll_entry"]["poll_in_nfds1"] = 1

        # Save values of local variables to print in case of test failure
        self.recorded_values["poll_entry"] = locals()

    def poll_exit(self, event):
        ret = event["ret"]
        fds_length = event["fds_length"]

        # check that only one FD is set, that it has the POLLIN flag and that
        # the raw value matches the events bit field.
        if ret == 1 and fds_length == 1:
            fd_0 = event["fds"][0]
            if (
                fd_0["raw_events"] == 0x1
                and fd_0["events"]["POLLIN"] == 1
                and fd_0["events"]["padding"] == 0
            ):
                self.expect["poll_exit"]["poll_out_nfds1"] = 1

        # Save values of local variables to print in case of test failure
        self.recorded_values["poll_exit"] = locals()

    def epoll_ctl_entry(self, event):
        epfd = event["epfd"]
        op_enum = event["op_enum"]
        fd = event["fd"]
        _event = event["event"]

        # check that we have FD 0 waiting for EPOLLIN|EPOLLPRI and that
        # data.fd = 0
        if (
            (epfd == self.epoll_wait_fd or epfd == self.epoll_pwait_fd)
            and "EPOLL_CTL_ADD" in op_enum.labels
            and fd == 0
            and _event["data_union"]["fd"] == 0
            and _event["events"]["EPOLLIN"] == 1
            and _event["events"]["EPOLLPRI"] == 1
        ):
            self.expect["epoll_ctl_entry"]["epoll_ctl_in_add"] = 1

        # Save values of local variables to print in case of test failure
        self.recorded_values["epoll_ctl_entry"] = locals()

    def epoll_ctl_exit(self, event):
        ret = event["ret"]

        if ret == 0:
            self.expect["epoll_ctl_exit"]["epoll_ctl_out_ok"] = 1

        # Save values of local variables to print in case of test failure
        self.recorded_values["epoll_ctl_exit"] = locals()

    def epoll_wait_entry(self, event):
        epfd = event["epfd"]
        maxevents = event["maxevents"]
        timeout = event["timeout"]

        if epfd == self.epoll_wait_fd and maxevents == 1 and timeout == -1:
            self.expect["epoll_wait_entry"]["epoll_wait_in_ok"] = 1

        # Save values of local variables to print in case of test failure
        self.recorded_values["epoll_wait_entry"] = locals()

    def epoll_wait_exit(self, event):
        ret = event["ret"]
        fds_length = event["fds_length"]
        overflow = event["overflow"]

        # check that FD 0 returned with EPOLLIN and the right data.fd
        if ret == 1 and fds_length == 1:
            fd_0 = event["fds"][0]
            if (
                overflow == 0
                and fd_0["data_union"]["fd"] == 0
                and fd_0["events"]["EPOLLIN"] == 1
            ):
                self.expect["epoll_wait_exit"]["epoll_wait_out_fd0"] = 1

        # Save values of local variables to print in case of test failure
        self.recorded_values["epoll_wait_exit"] = locals()

    def epoll_pwait_entry(self, event):
        epfd = event["epfd"]
        maxevents = event["maxevents"]
        timeout = event["timeout"]

        if epfd == self.epoll_pwait_fd and maxevents == 1 and timeout == -1:
            self.expect["epoll_pwait_entry"]["epoll_pwait_in_ok"] = 1

        # Save values of local variables to print in case of test failure
        self.recorded_values["epoll_pwait_entry"] = locals()

    def epoll_pwait_exit(self, event):
        ret = event["ret"]
        fds_length = event["fds_length"]
        overflow = event["overflow"]

        # check that FD 0 returned with EPOLLIN and the right data.fd
        if ret == 1 and fds_length == 1:
            fd_0 = event["fds"][0]
            if (
                overflow == 0
                and fd_0["data_union"]["fd"] == 0
                and fd_0["events"]["EPOLLIN"] == 1
            ):
                self.expect["epoll_pwait_exit"]["epoll_pwait_out_fd0"] = 1

        # Save values of local variables to print in case of test failure
        self.recorded_values["epoll_pwait_exit"] = locals()


class WorkingCasesTimeout(TraceParser):
    def __init__(self, trace, validation_args):
        super().__init__(trace, validation_args["pid"])
        self.expect["select_entry"]["select_timeout_in_fd0"] = 0
        self.expect["select_entry"]["select_timeout_in_fd1023"] = 0
        self.expect["select_exit"]["select_timeout_out"] = 0
        self.expect["poll_entry"]["poll_timeout_in"] = 0
        self.expect["poll_exit"]["poll_timeout_out"] = 0
        self.expect["epoll_ctl_entry"]["epoll_ctl_timeout_in_add"] = 0
        self.expect["epoll_ctl_exit"]["epoll_ctl_timeout_out_ok"] = 0
        self.expect["epoll_wait_entry"]["epoll_wait_timeout_in"] = 0
        self.expect["epoll_wait_exit"]["epoll_wait_timeout_out"] = 0

    def select_entry(self, event):
        n = event["n"]
        tvp = event["tvp"]

        if n == 1 and tvp != 0:
            self.expect["select_entry"]["select_timeout_in_fd0"] = 1
        if n == 1023:
            readfd_127 = event["readfds"][127]
            writefd_127 = event["writefds"][127]
            exceptfd_127 = event["exceptfds"][127]

            if (
                readfd_127 == 0x40
                and writefd_127 == 0
                and exceptfd_127 == 0
                and tvp != 0
            ):
                self.expect["select_entry"]["select_timeout_in_fd1023"] = 1

        # Save values of local variables to print in case of test failure
        self.recorded_values["select_entry"] = locals()

    def select_exit(self, event):
        ret = event["ret"]
        tvp = event["tvp"]

        if ret == 0 and tvp != 0:
            self.expect["select_exit"]["select_timeout_out"] = 1

        # Save values of local variables to print in case of test failure
        self.recorded_values["select_exit"] = locals()

    def poll_entry(self, event):
        nfds = event["nfds"]
        fds_length = event["fds_length"]

        # check that we wait on FD 0 for POLLIN and that the raw_events
        # field matches the value of POLLIN
        if nfds == 1 and fds_length == 1:
            fd_0 = event["fds"][0]
            if (
                fd_0["raw_events"] == 0x3
                and fd_0["events"]["POLLIN"] == 1
                and fd_0["events"]["padding"] == 0
            ):
                self.expect["poll_entry"]["poll_timeout_in"] = 1

        # Save values of local variables to print in case of test failure
        self.recorded_values["poll_entry"] = locals()

    def poll_exit(self, event):
        ret = event["ret"]
        nfds = event["nfds"]
        fds_length = event["fds_length"]

        if ret == 0 and nfds == 1 and fds_length == 0:
            self.expect["poll_exit"]["poll_timeout_out"] = 1

        # Save values of local variables to print in case of test failure
        self.recorded_values["poll_exit"] = locals()

    def epoll_ctl_entry(self, event):
        op_enum = event["op_enum"]
        _event = event["event"]

        # make sure we see a EPOLLIN|EPOLLPRI
        if (
            "EPOLL_CTL_ADD" in op_enum.labels
            and _event["events"]["EPOLLIN"] == 1
            and _event["events"]["EPOLLPRI"] == 1
        ):
            self.expect["epoll_ctl_entry"]["epoll_ctl_timeout_in_add"] = 1

        # Save values of local variables to print in case of test failure
        self.recorded_values["epoll_ctl_entry"] = locals()

    def epoll_ctl_exit(self, event):
        ret = event["ret"]

        if ret == 0:
            self.expect["epoll_ctl_exit"]["epoll_ctl_timeout_out_ok"] = 1

        # Save values of local variables to print in case of test failure
        self.recorded_values["epoll_ctl_exit"] = locals()

    def epoll_wait_entry(self, event):
        maxevents = event["maxevents"]
        timeout = event["timeout"]

        if maxevents == 1 and timeout == 1:
            self.expect["epoll_wait_entry"]["epoll_wait_timeout_in"] = 1

        # Save values of local variables to print in case of test failure
        self.recorded_values["epoll_wait_entry"] = locals()

    def epoll_wait_exit(self, event):
        ret = event["ret"]
        fds_length = event["fds_length"]
        overflow = event["overflow"]

        if ret == 0 and fds_length == 0 and overflow == 0:
            self.expect["epoll_wait_exit"]["epoll_wait_timeout_out"] = 1

        # Save values of local variables to print in case of test failure
        self.recorded_values["epoll_wait_exit"] = locals()


class PselectInvalidFd(TraceParser):
    def __init__(self, trace, validation_args):
        super().__init__(trace, validation_args["pid"])
        self.expect["select_entry"]["select_invalid_fd_in"] = 0
        self.expect["select_exit"]["select_invalid_fd_out"] = 0

    def select_entry(self, event):
        n = event["n"]
        overflow = event["overflow"]

        if n > 0 and overflow == 0:
            self.expect["select_entry"]["select_invalid_fd_in"] = 1

        # Save values of local variables to print in case of test failure
        self.recorded_values["select_entry"] = locals()

    def select_exit(self, event):
        ret = event["ret"]
        overflow = event["overflow"]
        _readfds_length = event["_readfds_length"]

        # make sure the event has a ret field equal to -EBADF
        if ret == -9 and overflow == 0 and _readfds_length == 0:
            self.expect["select_exit"]["select_invalid_fd_out"] = 1

        # Save values of local variables to print in case of test failure
        self.recorded_values["select_exit"] = locals()


class PpollBig(TraceParser):
    def __init__(self, trace, validation_args):
        super().__init__(trace, validation_args["pid"])
        self.expect["poll_entry"]["big_poll_in"] = 0
        self.expect["poll_exit"]["big_poll_out"] = 0

    def poll_entry(self, event):
        nfds = event["nfds"]
        fds_length = event["fds_length"]
        overflow = event["overflow"]

        # test of big list of FDs and the behaviour of the overflow
        if nfds == 2047 and fds_length == 512 and overflow == 1:
            fd_0 = event["fds"][0]
            fd_511 = event["fds"][511]
            if (
                fd_0["raw_events"] == 0x3
                and fd_0["events"]["POLLIN"] == 1
                and fd_0["events"]["padding"] == 0
                and fd_511["events"]["POLLIN"] == 1
                and fd_511["events"]["POLLPRI"] == 1
            ):
                self.expect["poll_entry"]["big_poll_in"] = 1

        # Save values of local variables to print in case of test failure
        self.recorded_values["poll_entry"] = locals()

    def poll_exit(self, event):
        ret = event["ret"]
        nfds = event["nfds"]
        fds_length = event["fds_length"]
        overflow = event["overflow"]

        # test of big list of FDs and the behaviour of the overflow
        if ret == 2047 and nfds == 2047 and fds_length == 512 and overflow == 1:
            fd_0 = event["fds"][0]
            fd_511 = event["fds"][511]
            if fd_0["events"]["POLLIN"] == 1 and fd_511["events"]["POLLIN"] == 1:
                self.expect["poll_exit"]["big_poll_out"] = 1

        # Save values of local variables to print in case of test failure
        self.recorded_values["poll_exit"] = locals()


class PpollFdsBufferOverflow(TraceParser):
    def __init__(self, trace, validation_args):
        super().__init__(trace, validation_args["pid"])
        self.expect["poll_entry"]["poll_overflow_in"] = 0
        self.expect["poll_exit"]["poll_overflow_out"] = 0

    def poll_entry(self, event):
        nfds = event["nfds"]
        fds_length = event["fds_length"]
        overflow = event["overflow"]

        # test that event in valid even though the target buffer is too small
        # and the program segfaults
        if nfds == 100 and fds_length == 100 and overflow == 0:
            fd_0 = event["fds"][0]
            if fd_0["events"]["POLLIN"] == 1:
                self.expect["poll_entry"]["poll_overflow_in"] = 1

        # Save values of local variables to print in case of test failure
        self.recorded_values["poll_entry"] = locals()

    def poll_exit(self, event):
        nfds = event["nfds"]
        overflow = event["overflow"]

        # test that event in valid even though the target buffer is too small
        # and the program segfaults
        if nfds == 100 and overflow == 0:
            self.expect["poll_exit"]["poll_overflow_out"] = 1

        # Save values of local variables to print in case of test failure
        self.recorded_values["poll_exit"] = locals()


class PselectInvalidPointer(TraceParser):
    def __init__(self, trace, validation_args):
        super().__init__(trace, validation_args["pid"])
        self.expect["select_entry"]["pselect_invalid_in"] = 0
        self.expect["select_exit"]["pselect_invalid_out"] = 0

    def select_entry(self, event):
        n = event["n"]
        overflow = event["overflow"]
        _readfds_length = event["_readfds_length"]

        # test that event in valid even though the target buffer pointer is
        # invalid and the program segfaults
        if n == 1 and overflow == 0 and _readfds_length == 0:
            self.expect["select_entry"]["pselect_invalid_in"] = 1

        # Save values of local variables to print in case of test failure
        self.recorded_values["select_entry"] = locals()

    def select_exit(self, event):
        ret = event["ret"]
        overflow = event["overflow"]
        _readfds_length = event["_readfds_length"]

        # test that event in valid even though the target buffer pointer is
        # invalid and the program segfaults
        if ret == -14 and overflow == 0 and _readfds_length == 0:
            self.expect["select_exit"]["pselect_invalid_out"] = 1

        # Save values of local variables to print in case of test failure
        self.recorded_values["select_exit"] = locals()


class PpollFdsULongMax(TraceParser):
    def __init__(self, trace, validation_args):
        super().__init__(trace, validation_args["pid"])
        self.expect["poll_entry"]["poll_max_in"] = 0
        self.expect["poll_exit"]["poll_max_out"] = 0

    def poll_entry(self, event):
        nfds = event["nfds"]
        overflow = event["overflow"]

        # check the proper working of INT_MAX maxevent value
        if nfds == 4294967295 and overflow == 1:
            self.expect["poll_entry"]["poll_max_in"] = 1

        # Save values of local variables to print in case of test failure
        self.recorded_values["poll_entry"] = locals()

    def poll_exit(self, event):
        ret = event["ret"]
        nfds = event["nfds"]
        overflow = event["overflow"]

        # check the proper working of UINT_MAX maxevent value
        if ret == -22 and nfds == 4294967295 and overflow == 0:
            self.expect["poll_exit"]["poll_max_out"] = 1

        # Save values of local variables to print in case of test failure
        self.recorded_values["poll_exit"] = locals()


class EpollPwaitInvalidPointer(TraceParser):
    def __init__(self, trace, validation_args):
        super().__init__(trace, validation_args["pid"])

        # Values expected in the trace
        self.epoll_fd = validation_args["epollfd"]

        self.expect["epoll_wait_entry"]["epoll_wait_invalid_in"] = 0
        self.expect["epoll_wait_exit"]["epoll_wait_invalid_out"] = 0

    def epoll_wait_entry(self, event):
        epfd = event["epfd"]
        maxevents = event["maxevents"]
        timeout = event["timeout"]

        # test that event in valid even though the target buffer pointer is
        # invalid and the program segfaults
        if epfd == self.epoll_fd and maxevents == 1 and timeout == -1:
            self.expect["epoll_wait_entry"]["epoll_wait_invalid_in"] = 1

        # Save values of local variables to print in case of test failure
        self.recorded_values["epoll_wait_entry"] = locals()

    def epoll_wait_exit(self, event):
        ret = event["ret"]
        fds_length = event["fds_length"]
        overflow = event["overflow"]

        # test that event in valid even though the target buffer pointer is
        # invalid and the program segfaults
        if ret == -14 and fds_length == 0 and overflow == 0:
            self.expect["epoll_wait_exit"]["epoll_wait_invalid_out"] = 1

        # Save values of local variables to print in case of test failure
        self.recorded_values["epoll_wait_exit"] = locals()


class EpollPwaitIntMax(TraceParser):
    def __init__(self, trace, validation_args):
        super().__init__(trace, validation_args["pid"])

        # Values expected in the trace
        self.epoll_fd = validation_args["epollfd"]

        self.expect["epoll_wait_entry"]["epoll_wait_max_in"] = 0
        self.expect["epoll_wait_exit"]["epoll_wait_max_out"] = 0

    def epoll_wait_entry(self, event):
        epfd = event["epfd"]
        maxevents = event["maxevents"]
        timeout = event["timeout"]

        # check the proper working of INT_MAX maxevent value
        if epfd == self.epoll_fd and maxevents == 2147483647 and timeout == -1:
            self.expect["epoll_wait_entry"]["epoll_wait_max_in"] = 1

        # Save values of local variables to print in case of test failure
        self.recorded_values["epoll_wait_entry"] = locals()

    def epoll_wait_exit(self, event):
        ret = event["ret"]
        fds_length = event["fds_length"]
        overflow = event["overflow"]

        # check the proper working of INT_MAX maxevent value
        if ret == -22 and fds_length == 0 and overflow == 0:
            self.expect["epoll_wait_exit"]["epoll_wait_max_out"] = 1

        # Save values of local variables to print in case of test failure
        self.recorded_values["epoll_wait_exit"] = locals()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Trace parser")
    parser.add_argument("path", metavar="<path/to/trace>", help="Trace path")
    parser.add_argument("-t", "--test", type=str, help="Test to validate")
    parser.add_argument(
        "-o", "--validation-file", type=str, help="Validation file path"
    )
    args = parser.parse_args()

    if not args.test:
        print("Need to pass a test to validate (--test/-t)")
        sys.exit(1)

    if not args.validation_file:
        print("Need to pass the test validation file (--validation-file/-o)")
        sys.exit(1)

    traces = bt2.TraceCollectionMessageIterator(args.path)

    with open(args.validation_file) as f:
        try:
            test_validation_args = json.load(f)
        except Exception as e:
            print("Failed to parse validation file: " + str(e))
            sys.exit(1)

    t = None

    if args.test == "working_cases":
        t = WorkingCases(traces, test_validation_args)
    elif args.test == "working_cases_timeout":
        t = WorkingCasesTimeout(traces, test_validation_args)
    elif args.test == "pselect_invalid_fd":
        t = PselectInvalidFd(traces, test_validation_args)
    elif args.test == "ppoll_big":
        t = PpollBig(traces, test_validation_args)
    elif args.test == "ppoll_fds_buffer_overflow":
        t = PpollFdsBufferOverflow(traces, test_validation_args)
    elif args.test == "pselect_invalid_pointer":
        t = PselectInvalidPointer(traces, test_validation_args)
    elif args.test == "ppoll_fds_ulong_max":
        t = PpollFdsULongMax(traces, test_validation_args)
    elif args.test == "epoll_pwait_invalid_pointer":
        t = EpollPwaitInvalidPointer(traces, test_validation_args)
    elif args.test == "epoll_pwait_int_max":
        t = EpollPwaitIntMax(traces, test_validation_args)
    elif args.test == "ppoll_concurrent_write":
        # stress test, nothing reliable to check
        ret = 0
    elif args.test == "epoll_pwait_concurrent_munmap":
        # stress test, nothing reliable to check
        ret = 0
    else:
        print("Invalid test case")
        sys.exit(1)

    if t is not None:
        ret = t.parse()

    sys.exit(ret)
