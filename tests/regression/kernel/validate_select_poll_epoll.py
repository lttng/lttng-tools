#!/usr/bin/env python3

import sys
import time
import argparse

NSEC_PER_SEC = 1000000000

try:
    from babeltrace import TraceCollection
except ImportError:
    # quick fix for debian-based distros
    sys.path.append("/usr/local/lib/python%d.%d/site-packages" %
                    (sys.version_info.major, sys.version_info.minor))
    from babeltrace import TraceCollection


class TraceParser:
    def __init__(self, trace, pid):
        self.trace = trace
        self.pid = pid
        self.expect = {}

    def ns_to_hour_nsec(self, ns):
        d = time.localtime(ns/NSEC_PER_SEC)
        return "%02d:%02d:%02d.%09d" % (d.tm_hour, d.tm_min, d.tm_sec,
                                        ns % NSEC_PER_SEC)

    def parse(self):
        # iterate over all the events
        for event in self.trace.events:
            if self.pid is not None and event["pid"] != self.pid:
                continue

            method_name = "handle_%s" % event.name.replace(":", "_").replace(
                "+", "_")
            # call the function to handle each event individually
            if hasattr(TraceParser, method_name):
                func = getattr(TraceParser, method_name)
                func(self, event)

        ret = 0
        for i in self.expect.keys():
            if self.expect[i] == 0:
                print("%s not validated" % i)
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
        self.epoll_wait_entry(event)

    def handle_compat_syscall_exit_epoll_pwait(self, event):
        self.epoll_wait_exit(event)

    def handle_syscall_entry_epoll_pwait(self, event):
        self.epoll_wait_entry(event)

    def handle_syscall_exit_epoll_pwait(self, event):
        self.epoll_wait_exit(event)

    def epoll_wait_entry(self, event):
        pass

    def epoll_wait_exit(self, event):
        pass

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


class Test1(TraceParser):
    def __init__(self, trace, pid):
        super().__init__(trace, pid)
        self.expect["select_in_fd0"] = 0
        self.expect["select_in_fd1023"] = 0
        self.expect["select_out_fd0"] = 0
        self.expect["select_out_fd1023"] = 0
        self.expect["poll_in_nfds1"] = 0
        self.expect["poll_out_nfds1"] = 0
        self.expect["epoll_ctl_in_add"] = 0
        self.expect["epoll_ctl_out_ok"] = 0
        self.expect["epoll_wait_in_ok"] = 0
        self.expect["epoll_wait_out_fd0"] = 0

    def select_entry(self, event):
        timestamp = event.timestamp
        cpu_id = event["cpu_id"]
        n = event["n"]
        overflow = event["overflow"]
        tvp = event["tvp"]
        _readfds_length = event["_readfds_length"]
        readfds = event["readfds"]
        _writefds_length = event["_writefds_length"]
        writefds = event["writefds"]
        _exceptfds_length = event["_exceptfds_length"]
        exceptfds = event["exceptfds"]

        # check that the FD 0 is actually set in the readfds
        if n == 1 and readfds[0] == 1:
            self.expect["select_in_fd0"] = 1
        if n == 1023:
            # check that the FD 1023 is actually set in the readfds
            if readfds[127] == 0x40 and writefds[127] == 0 and \
                    exceptfds[127] == 0 and overflow == 0:
                self.expect["select_in_fd1023"] = 1

    def select_exit(self, event):
        timestamp = event.timestamp
        cpu_id = event["cpu_id"]
        ret = event["ret"]
        overflow = event["overflow"]
        tvp = event["tvp"]
        _readfds_length = event["_readfds_length"]
        readfds = event["readfds"]
        _writefds_length = event["_writefds_length"]
        writefds = event["writefds"]
        _exceptfds_length = event["_exceptfds_length"]
        exceptfds = event["exceptfds"]

        if ret == 1:
            # check that the FD 0 is actually set in the readfds
            if readfds[0] == 1:
                self.expect["select_out_fd0"] = 1
            # check that the FD 1023 is actually set in the readfds
            if _readfds_length == 128 and readfds[127] == 0x40 and \
                    writefds[127] == 0 and exceptfds[127] == 0 and tvp == 0:
                self.expect["select_out_fd1023"] = 1

    def poll_entry(self, event):
        timestamp = event.timestamp
        cpu_id = event["cpu_id"]
        nfds = event["nfds"]
        fds_length = event["fds_length"]
        overflow = event["overflow"]
        fds = event["fds"]

        # check that only one FD is set, that it has the POLLIN flag and that
        # the raw value matches the events bit field.
        if nfds == 1 and fds_length == 1 and fds[0]["raw_events"] == 0x3 \
                and fds[0]["events"]["POLLIN"] == 1 and \
                fds[0]["events"]["padding"] == 0:
            self.expect["poll_in_nfds1"] = 1

    def poll_exit(self, event):
        timestamp = event.timestamp
        cpu_id = event["cpu_id"]
        ret = event["ret"]
        nfds = event["nfds"]
        fds_length = event["fds_length"]
        fds = event["fds"]

        # check that only one FD is set, that it has the POLLIN flag and that
        # the raw value matches the events bit field.
        if ret == 1 and fds_length == 1 and fds[0]["raw_events"] == 0x1 \
                and fds[0]["events"]["POLLIN"] == 1 and \
                fds[0]["events"]["padding"] == 0:
            self.expect["poll_out_nfds1"] = 1

    def epoll_ctl_entry(self, event):
        timestamp = event.timestamp
        cpu_id = event["cpu_id"]
        epfd = event["epfd"]
        op_enum = event["op_enum"]
        fd = event["fd"]
        _event = event["event"]

        # check that we have FD 0 waiting for EPOLLIN|EPOLLPRI and that
        # data.fd = 0
        if epfd == 3 and op_enum == "EPOLL_CTL_ADD" and fd == 0 and \
                _event["data_union"]["fd"] == 0 and \
                _event["events"]["EPOLLIN"] == 1 and \
                _event["events"]["EPOLLPRI"] == 1:
            self.expect["epoll_ctl_in_add"] = 1

    def epoll_ctl_exit(self, event):
        timestamp = event.timestamp
        cpu_id = event["cpu_id"]
        ret = event["ret"]

        if ret == 0:
            self.expect["epoll_ctl_out_ok"] = 1

    def epoll_wait_entry(self, event):
        timestamp = event.timestamp
        cpu_id = event["cpu_id"]
        epfd = event["epfd"]
        maxevents = event["maxevents"]
        timeout = event["timeout"]

        if epfd == 3 and maxevents == 1 and timeout == -1:
            self.expect["epoll_wait_in_ok"] = 1

    def epoll_wait_exit(self, event):
        timestamp = event.timestamp
        cpu_id = event["cpu_id"]
        ret = event["ret"]
        fds_length = event["fds_length"]
        overflow = event["overflow"]
        fds = event["fds"]

        # check that FD 0 returned with EPOLLIN and the right data.fd
        if ret == 1 and fds_length == 1 and overflow == 0 and \
                fds[0]["data_union"]["fd"] == 0 and \
                fds[0]["events"]["EPOLLIN"] == 1:
            self.expect["epoll_wait_out_fd0"] = 1


class Test2(TraceParser):
    def __init__(self, trace, pid):
        super().__init__(trace, pid)
        self.expect["select_timeout_in_fd0"] = 0
        self.expect["select_timeout_in_fd1023"] = 0
        self.expect["select_timeout_out"] = 0
        self.expect["poll_timeout_in"] = 0
        self.expect["poll_timeout_out"] = 0
        self.expect["epoll_ctl_timeout_in_add"] = 0
        self.expect["epoll_ctl_timeout_out_ok"] = 0
        self.expect["epoll_wait_timeout_in"] = 0
        self.expect["epoll_wait_timeout_out"] = 0

    def select_entry(self, event):
        timestamp = event.timestamp
        cpu_id = event["cpu_id"]
        n = event["n"]
        overflow = event["overflow"]
        tvp = event["tvp"]
        _readfds_length = event["_readfds_length"]
        readfds = event["readfds"]
        _writefds_length = event["_writefds_length"]
        writefds = event["writefds"]
        _exceptfds_length = event["_exceptfds_length"]
        exceptfds = event["exceptfds"]

        if n == 1 and tvp != 0:
            self.expect["select_timeout_in_fd0"] = 1
        if n == 1023:
            if readfds[127] == 0x40 and writefds[127] == 0 and \
                    exceptfds[127] == 0 and tvp != 0:
                self.expect["select_timeout_in_fd1023"] = 1

    def select_exit(self, event):
        timestamp = event.timestamp
        cpu_id = event["cpu_id"]
        ret = event["ret"]
        overflow = event["overflow"]
        tvp = event["tvp"]
        _readfds_length = event["_readfds_length"]
        readfds = event["readfds"]
        _writefds_length = event["_writefds_length"]
        writefds = event["writefds"]
        _exceptfds_length = event["_exceptfds_length"]
        exceptfds = event["exceptfds"]

        if ret == 0 and tvp != 0:
            self.expect["select_timeout_out"] = 1

    def poll_entry(self, event):
        timestamp = event.timestamp
        cpu_id = event["cpu_id"]
        nfds = event["nfds"]
        fds_length = event["fds_length"]
        overflow = event["overflow"]
        fds = event["fds"]

        # check that we wait on FD 0 for POLLIN and that the raw_events
        # field matches the value of POLLIN
        if nfds == 1 and fds_length == 1 and fds[0]["raw_events"] == 0x3 \
                and fds[0]["events"]["POLLIN"] == 1 and \
                fds[0]["events"]["padding"] == 0:
            self.expect["poll_timeout_in"] = 1

    def poll_exit(self, event):
        timestamp = event.timestamp
        cpu_id = event["cpu_id"]
        ret = event["ret"]
        nfds = event["nfds"]
        fds_length = event["fds_length"]
        fds = event["fds"]

        if ret == 0 and nfds == 1 and fds_length == 0:
            self.expect["poll_timeout_out"] = 1

    def epoll_ctl_entry(self, event):
        timestamp = event.timestamp
        cpu_id = event["cpu_id"]
        epfd = event["epfd"]
        op_enum = event["op_enum"]
        fd = event["fd"]
        _event = event["event"]

        # make sure we see a EPOLLIN|EPOLLPRI
        if op_enum == "EPOLL_CTL_ADD" and \
                _event["events"]["EPOLLIN"] == 1 and \
                _event["events"]["EPOLLPRI"] == 1:
            self.expect["epoll_ctl_timeout_in_add"] = 1

    def epoll_ctl_exit(self, event):
        timestamp = event.timestamp
        cpu_id = event["cpu_id"]
        ret = event["ret"]

        if ret == 0:
            self.expect["epoll_ctl_timeout_out_ok"] = 1

    def epoll_wait_entry(self, event):
        timestamp = event.timestamp
        cpu_id = event["cpu_id"]
        epfd = event["epfd"]
        maxevents = event["maxevents"]
        timeout = event["timeout"]

        if maxevents == 1 and timeout == 1:
            self.expect["epoll_wait_timeout_in"] = 1

    def epoll_wait_exit(self, event):
        timestamp = event.timestamp
        cpu_id = event["cpu_id"]
        ret = event["ret"]
        fds_length = event["fds_length"]
        overflow = event["overflow"]
        fds = event["fds"]

        if ret == 0 and fds_length == 0 and overflow == 0:
            self.expect["epoll_wait_timeout_out"] = 1


class Test3(TraceParser):
    def __init__(self, trace, pid):
        super().__init__(trace, pid)
        self.expect["select_too_big_in"] = 0
        self.expect["select_too_big_out"] = 0

    def select_entry(self, event):
        timestamp = event.timestamp
        cpu_id = event["cpu_id"]
        n = event["n"]
        overflow = event["overflow"]
        tvp = event["tvp"]
        _readfds_length = event["_readfds_length"]
        readfds = event["readfds"]
        _writefds_length = event["_writefds_length"]
        writefds = event["writefds"]
        _exceptfds_length = event["_exceptfds_length"]
        exceptfds = event["exceptfds"]

        # make sure an invalid value still produces a valid event
        if n == 2048 and overflow == 0 and _readfds_length == 0:
            self.expect["select_too_big_in"] = 1

    def select_exit(self, event):
        timestamp = event.timestamp
        cpu_id = event["cpu_id"]
        ret = event["ret"]
        overflow = event["overflow"]
        tvp = event["tvp"]
        _readfds_length = event["_readfds_length"]
        readfds = event["readfds"]
        _writefds_length = event["_writefds_length"]
        writefds = event["writefds"]
        _exceptfds_length = event["_exceptfds_length"]
        exceptfds = event["exceptfds"]

        # make sure an invalid value still produces a valid event
        if ret == -9 and overflow == 0 and _readfds_length == 0:
            self.expect["select_too_big_out"] = 1


class Test4(TraceParser):
    def __init__(self, trace, pid):
        super().__init__(trace, pid)
        self.expect["big_poll_in"] = 0
        self.expect["big_poll_out"] = 0

    def poll_entry(self, event):
        timestamp = event.timestamp
        cpu_id = event["cpu_id"]
        nfds = event["nfds"]
        fds_length = event["fds_length"]
        overflow = event["overflow"]
        fds = event["fds"]

        # test of big list of FDs and the behaviour of the overflow
        if nfds == 2047 and fds_length == 512 and overflow == 1 and \
                fds[0]["raw_events"] == 0x3 \
                and fds[0]["events"]["POLLIN"] == 1 and \
                fds[0]["events"]["padding"] == 0 and \
                fds[511]["events"]["POLLIN"] == 1 and \
                fds[511]["events"]["POLLPRI"] == 1:
            self.expect["big_poll_in"] = 1

    def poll_exit(self, event):
        timestamp = event.timestamp
        cpu_id = event["cpu_id"]
        ret = event["ret"]
        nfds = event["nfds"]
        fds_length = event["fds_length"]
        overflow = event["overflow"]
        fds = event["fds"]

        # test of big list of FDs and the behaviour of the overflow
        if ret == 2047 and nfds == 2047 and fds_length == 512 and \
                overflow == 1 and fds[0]["events"]["POLLIN"] == 1 and \
                fds[511]["events"]["POLLIN"] == 1:
            self.expect["big_poll_out"] = 1


class Test5(TraceParser):
    def __init__(self, trace, pid):
        super().__init__(trace, pid)
        self.expect["poll_overflow_in"] = 0
        self.expect["poll_overflow_out"] = 0

    def poll_entry(self, event):
        timestamp = event.timestamp
        cpu_id = event["cpu_id"]
        nfds = event["nfds"]
        fds_length = event["fds_length"]
        overflow = event["overflow"]
        fds = event["fds"]

        # test that event in valid even though the target buffer is too small
        # and the program segfaults
        if nfds == 100 and fds_length == 100 and overflow == 0 and \
                fds[0]["events"]["POLLIN"] == 1:
            self.expect["poll_overflow_in"] = 1

    def poll_exit(self, event):
        timestamp = event.timestamp
        cpu_id = event["cpu_id"]
        ret = event["ret"]
        nfds = event["nfds"]
        fds_length = event["fds_length"]
        overflow = event["overflow"]
        fds = event["fds"]

        # test that event in valid even though the target buffer is too small
        # and the program segfaults
        if nfds == 100 and overflow == 0:
            self.expect["poll_overflow_out"] = 1


class Test6(TraceParser):
    def __init__(self, trace, pid):
        super().__init__(trace, pid)
        self.expect["pselect_invalid_in"] = 0
        self.expect["pselect_invalid_out"] = 0

    def select_entry(self, event):
        timestamp = event.timestamp
        cpu_id = event["cpu_id"]
        n = event["n"]
        overflow = event["overflow"]
        tvp = event["tvp"]
        _readfds_length = event["_readfds_length"]
        readfds = event["readfds"]
        _writefds_length = event["_writefds_length"]
        writefds = event["writefds"]
        _exceptfds_length = event["_exceptfds_length"]
        exceptfds = event["exceptfds"]

        # test that event in valid even though the target buffer pointer is
        # invalid and the program segfaults
        if n == 1 and overflow == 0 and _readfds_length == 0:
            self.expect["pselect_invalid_in"] = 1

    def select_exit(self, event):
        timestamp = event.timestamp
        cpu_id = event["cpu_id"]
        ret = event["ret"]
        overflow = event["overflow"]
        tvp = event["tvp"]
        _readfds_length = event["_readfds_length"]
        readfds = event["readfds"]
        _writefds_length = event["_writefds_length"]
        writefds = event["writefds"]
        _exceptfds_length = event["_exceptfds_length"]
        exceptfds = event["exceptfds"]

        # test that event in valid even though the target buffer pointer is
        # invalid and the program segfaults
        if ret == -14 and overflow == 0 and _readfds_length == 0:
            self.expect["pselect_invalid_out"] = 1


class Test7(TraceParser):
    def __init__(self, trace, pid):
        super().__init__(trace, pid)
        self.expect["poll_max_in"] = 0
        self.expect["poll_max_out"] = 0

    def poll_entry(self, event):
        timestamp = event.timestamp
        cpu_id = event["cpu_id"]
        nfds = event["nfds"]
        fds_length = event["fds_length"]
        overflow = event["overflow"]
        fds = event["fds"]

        # check the proper working of INT_MAX maxevent value
        if nfds == 4294967295 and overflow == 1:
            self.expect["poll_max_in"] = 1

    def poll_exit(self, event):
        timestamp = event.timestamp
        cpu_id = event["cpu_id"]
        ret = event["ret"]
        nfds = event["nfds"]
        fds_length = event["fds_length"]
        overflow = event["overflow"]
        fds = event["fds"]

        # check the proper working of UINT_MAX maxevent value
        if ret == -22 and nfds == 4294967295 and overflow == 0:
            self.expect["poll_max_out"] = 1


class Test8(TraceParser):
    def __init__(self, trace, pid):
        super().__init__(trace, pid)
        self.expect["epoll_wait_invalid_in"] = 0
        self.expect["epoll_wait_invalid_out"] = 0

    def epoll_wait_entry(self, event):
        timestamp = event.timestamp
        cpu_id = event["cpu_id"]
        epfd = event["epfd"]
        maxevents = event["maxevents"]
        timeout = event["timeout"]

        # test that event in valid even though the target buffer pointer is
        # invalid and the program segfaults
        if epfd == 3 and maxevents == 1 and timeout == -1:
            self.expect["epoll_wait_invalid_in"] = 1

    def epoll_wait_exit(self, event):
        timestamp = event.timestamp
        cpu_id = event["cpu_id"]
        ret = event["ret"]
        fds_length = event["fds_length"]
        overflow = event["overflow"]
        fds = event["fds"]

        # test that event in valid even though the target buffer pointer is
        # invalid and the program segfaults
        if ret == -14 and fds_length == 0 and overflow == 0:
            self.expect["epoll_wait_invalid_out"] = 1


class Test9(TraceParser):
    def __init__(self, trace, pid):
        super().__init__(trace, pid)
        self.expect["epoll_wait_max_in"] = 0
        self.expect["epoll_wait_max_out"] = 0

    def epoll_wait_entry(self, event):
        timestamp = event.timestamp
        cpu_id = event["cpu_id"]
        epfd = event["epfd"]
        maxevents = event["maxevents"]
        timeout = event["timeout"]

        # check the proper working of INT_MAX maxevent value
        if epfd == 3 and maxevents == 2147483647 and timeout == -1:
            self.expect["epoll_wait_max_in"] = 1

    def epoll_wait_exit(self, event):
        timestamp = event.timestamp
        cpu_id = event["cpu_id"]
        ret = event["ret"]
        fds_length = event["fds_length"]
        overflow = event["overflow"]
        fds = event["fds"]

        # check the proper working of INT_MAX maxevent value
        if ret == -22 and fds_length == 0 and overflow == 0:
            self.expect["epoll_wait_max_out"] = 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Trace parser')
    parser.add_argument('path', metavar="<path/to/trace>", help='Trace path')
    parser.add_argument('-t', '--test', type=int, help='Test to validate')
    parser.add_argument('-p', '--pid', type=int, help='PID of the app')
    args = parser.parse_args()

    if not args.test:
        print("Need to pass a test to validate (-t)")
        sys.exit(1)

    if not args.pid:
        print("Need to pass the PID to check (-p)")
        sys.exit(1)

    traces = TraceCollection()
    handle = traces.add_traces_recursive(args.path, "ctf")
    if handle is None:
        sys.exit(1)

    t = None

    if args.test == 1:
        t = Test1(traces, args.pid)
    elif args.test == 2:
        t = Test2(traces, args.pid)
    elif args.test == 3:
        t = Test3(traces, args.pid)
    elif args.test == 4:
        t = Test4(traces, args.pid)
    elif args.test == 5:
        t = Test5(traces, args.pid)
    elif args.test == 6:
        t = Test6(traces, args.pid)
    elif args.test == 7:
        t = Test7(traces, args.pid)
    elif args.test == 8:
        t = Test8(traces, args.pid)
    elif args.test == 9:
        t = Test9(traces, args.pid)
    elif args.test == 10:
        # stress test, nothing reliable to check
        ret = 0
    elif args.test == 11:
        # stress test, nothing reliable to check
        ret = 0
    else:
        print("Invalid test case")
        sys.exit(1)

    if t is not None:
        ret = t.parse()

    for h in handle.values():
        traces.remove_trace(h)

    sys.exit(ret)
