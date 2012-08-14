#!/usr/bin/env python2

import os, sys
import subprocess
import threading
import Queue
import time

from signal import signal, SIGTERM, SIGINT

SESSIOND_BIN_NAME = "lttng-sessiond"
SESSIOND_BIN_PATH = "src/bin/lttng-sessiond/.libs/"
TESTDIR_PATH = ""

PRINT_BRACKET = "\033[1;34m[\033[1;33m+\033[1;34m]\033[00m"
PRINT_RED_BRACKET = "\033[1;31m[+]\033[00m"
PRINT_GREEN_BRACKET = "\033[1;32m[+]\033[00m"
PRINT_ARROW = "\033[1;32m-->\033[00m"

is_root = 1
no_stats = 0
stop_sampling = 1

top_cpu_legend = { 'us': "User CPU time", 'sy': "System CPU time",
        'id': "Idle CPU time", 'ni': "Nice CPU time", 'wa': "iowait",
        'hi': "Hardware IRQ", 'si': "Software Interrupts", 'st': "Steal Time", }

cpu_ret_q = Queue.Queue()
mem_ret_q = Queue.Queue()
test_ret_q = Queue.Queue()

global sdaemon_proc
global worker_proc

def cpu_create_usage_dict(top_line):
    """
    Return a dictionnary from a 'top' cpu line.
    Ex: Cpu(s):  2.1%us,  1.2%sy,  0.0%ni, 96.2%id,  0.4%wa,  0.0%hi,  0.0%si,  0.0%st
    """
    top_dict = {'us': 0, 'sy': 0, 'ni': 0, 'id': 0, 'wa': 0, 'hi': 0, 'si': 0, 'st': 0}

    # Split expression and remove first value which is "Cpu(s)"
    top_line = top_line.replace(",","")
    words = top_line.split()[1:]

    for word in words:
        index = word.find('%')
        # Add the value to the dictionnary
        top_dict[word[index + 1:]] = float(word[:index])

    return top_dict

def cpu_average_usage(top_lines):
    """
    Return a dictionnary of 'top' CPU stats but averaging all values.
    """
    avg_dict = {'us': 0, 'sy': 0, 'ni': 0, 'id': 0, 'wa': 0, 'hi': 0, 'si': 0, 'st': 0}
    # Average count
    count = 0.0

    for line in top_lines:
        tmp_dict = cpu_create_usage_dict(line)
        # Add value to avg dictionnary
        for key in tmp_dict:
            avg_dict[key] += tmp_dict[key]

        count += 1.0

    for key in avg_dict:
        avg_dict[key] = avg_dict[key] / count

    return (count, avg_dict)

def cpu_sample_usage(pid=None):
    """
    Sample CPU usage for num iterations.
    If num is greater than 1, the average will be computed.
    """
    args = ["top", "-b", "-n", "1"]
    if pid:
        args.append("-p")
        args.append(str(pid))

    # Spawn top process
    top = subprocess.Popen(args, stdout = subprocess.PIPE)

    grep = subprocess.Popen(["grep", "^Cpu"], stdin = top.stdout,
            stdout = subprocess.PIPE)
    top.stdout.close()

    return grep.communicate()[0].strip("\n")

def mem_sample_usage(pid):
    """
    Sample memory usage using /proc and a pid
    """
    args = ["cat", "/proc/" + str(pid) + "/status"]

    if not os.path.isfile(args[1]):
        return -1

    mem_proc = subprocess.Popen(args, stdout = subprocess.PIPE)

    grep = subprocess.Popen(["grep", "^VmRSS"], stdin = mem_proc.stdout,
            stdout = subprocess.PIPE)
    mem_proc.stdout.close()

    # Return virtual memory size in kilobytes (kB)
    #ret = grep.communicate()[0].split()
    ret = grep.communicate()[0].split()

    if len(ret) > 1:
        ret = ret[1]
    else:
        ret = 0

    return int(ret)

class SamplingWorker(threading.Thread):
    def __init__(self, s_type, worker = None, delay = 0.2, pid = 0):
        threading.Thread.__init__ (self)
        self.s_type = s_type
        self.delay = delay
        self.pid = pid
        self.worker = worker

    def run(self):
        count = 1
        lines = []

        if self.s_type == "cpu":
            while 1:
                if self.worker == None:
                    cpu_line = cpu_sample_usage(self.pid)
                    lines.append(cpu_line)
                    break
                elif self.worker.is_alive():
                    cpu_line = cpu_sample_usage(self.pid)
                    lines.append(cpu_line)
                else:
                    break

                # Delay sec per memory sampling
                time.sleep(self.delay)

            count, stats = cpu_average_usage(lines)
            cpu_ret_q.put((count, stats))
            # grep process has ended here

        elif self.s_type == "mem":
            count = 0
            mem_stat = 0

            while 1:
                if self.worker == None:
                    cpu_line = cpu_sample_usage(self.pid)
                    lines.append(cpu_line)
                    break
                elif self.worker.is_alive():
                    mem_stat += get_mem_usage(self.pid)
                    count += 1
                else:
                    break

                # Delay sec per memory sampling
                time.sleep(self.delay)

            mem_ret_q.put((count, mem_stat))

class TestWorker(threading.Thread):
    def __init__(self, path, name):
        threading.Thread.__init__(self)
        self.path = path
        self.name = name

    def run(self):
        bin_path_name = os.path.join(self.path, self.name)

        env = os.environ
        env['TEST_NO_SESSIOND'] = '1'

        test = subprocess.Popen([bin_path_name], env=env)
        test.wait()

        # Send ret value to main thread
        test_ret_q.put(test.returncode)

def get_pid(procname):
    """
    Return pid of process name using 'pidof' command
    """
    pidof = subprocess.Popen(["pidof", procname], stdout = subprocess.PIPE)
    pid = pidof.communicate()[0].split()

    if pid == []:
        return 0

    return int(pid[0])

def spawn_session_daemon():
    """
    Exec the session daemon and return PID
    """
    global sdaemon_proc

    pid = get_pid(SESSIOND_BIN_NAME)
    if pid != 0:
        os.kill(pid, SIGTERM)

    bin_path = os.path.join(TESTDIR_PATH, "..", SESSIOND_BIN_PATH, SESSIOND_BIN_NAME)

    if not os.path.isfile(bin_path):
        print "Error: No session daemon binary found. Compiled?"
        return 0

    try:
        sdaemon_proc = subprocess.Popen([bin_path, "-d"], shell=False,
                stderr = subprocess.PIPE)
    except OSError, e:
        print e
        return 0

    return get_pid(SESSIOND_BIN_NAME)

def start_test(name):
    """
    Spawn test and return exit code
    """
    tw = TestWorker(".", name)
    tw.start()

    return test_ret_q.get(True)

def print_cpu_stats(stats, count):
    """
    Pretty print on one line the CPU stats
    """
    sys.stdout.write(PRINT_ARROW + " Cpu [sampled %d time(s)]:\n   " % (count))
    for stat in stats:
        sys.stdout.write(" %s: %.2f, " % (stat, stats[stat]))
    print ""

def get_cpu_usage(delay=1, pid=0):
    """
    Spawn a worker thread to sample cpu usage.
    """
    sw = SamplingWorker("cpu", delay = delay, pid = pid)
    sw.start()

    return cpu_ret_q.get(True)

def get_mem_usage(pid):
    """
    Get memory usage for PID
    """
    return mem_sample_usage(pid)

def print_test_success(ret, expect):
    """
    Print if test has failed or pass according to the expected value.
    """
    if ret != expect:
        print "\n" + PRINT_RED_BRACKET + \
                " Failed: ret = %d (expected %d)" % (ret, expect)
        return 1
    else:
        print "\n" + PRINT_BRACKET + \
                " Passed: ret = %d (expected %d)" % (ret, expect)
        return 0

def run_test(test):
    """
    Run test 'name' and output report of the test with stats.
    """
    global worker_proc
    global sdaemon_proc
    dem_pid = 0     # Session daemon pid

    print PRINT_BRACKET + " %s" % (test['name'])
    print PRINT_ARROW + " %s" % (test['desc'])
    if no_stats:
        print PRINT_ARROW + " Statistics will NOT be collected"
    else:
        print PRINT_ARROW + " Statistics of the session daemon will be collected"

    if test['kern'] and not is_root:
        print "Needs root for kernel tracing. Skipping"
        return 0

    if not os.path.isfile(test['bin']):
        print "Unable to find test file '%s'. Skipping" % (test['bin'])
        return 0

    # No session daemon needed
    if not test['daemon']:
        print PRINT_ARROW + " No session daemon needed"
        ret = start_test(test['bin'])
        print_test_success(ret, test['success'])
        return 0
    else:
        print PRINT_ARROW + " Session daemon needed"

    dem_pid = spawn_session_daemon()
    if dem_pid <= 0:
        print "Unable to start %s. Stopping" % (SESSIOND_BIN_NAME)
        print sdaemon_proc.communicate()[1]
        return 0

    print PRINT_BRACKET + " Session daemon spawned (pid: %d)\n" % (dem_pid)

    if not no_stats:
        mem_before = get_mem_usage(dem_pid)
        print PRINT_BRACKET + " Stats *before* test:"
        print PRINT_ARROW + " Mem (kB): %d" % (mem_before)
        cpu_count, cpu_stats = get_cpu_usage(pid = dem_pid)
        print_cpu_stats(cpu_stats, cpu_count)

    tw = TestWorker(".", test['bin'])
    tw.start()

    if not no_stats:
        # Start CPU sampling for test
        sw_cpu = SamplingWorker("cpu", worker = tw, pid = dem_pid)
        sw_cpu.start()
        sw_mem = SamplingWorker("mem", worker = tw, pid = dem_pid)
        sw_mem.start()

    ret = test_ret_q.get(True)

    if not no_stats:
        time.sleep(2)
        # Compute memory average
        mem_count, mem_during = mem_ret_q.get(True)
        mem_during = float(mem_during) / float(mem_count)
        cpu_count, cpu_stats = cpu_ret_q.get(True)

        print "\n" + PRINT_BRACKET + " Stats *during* test:"
        print PRINT_ARROW + " Mem (kB): %.0f [sampled %d time(s)]" % (mem_during, mem_count)
        print_cpu_stats(cpu_stats, cpu_count)

        mem_after = get_mem_usage(dem_pid)
        print "\n" + PRINT_BRACKET + " Stats *after* test:"
        print PRINT_ARROW + " Mem (kB): %d" % (mem_after)
        cpu_count, cpu_stats = get_cpu_usage(pid = dem_pid)
        print_cpu_stats(cpu_stats, cpu_count)

        print "\n" + PRINT_BRACKET + " Memory usage differences:"
        print PRINT_ARROW + " Diff during and before (kB): %d" % (mem_during - mem_before)
        print PRINT_ARROW + " Diff during and after (kB): %d" % (mem_during - mem_after)
        print PRINT_ARROW + " Diff before and after (kB): %d" % (mem_after - mem_before)

    # Return value of 0 means that is passed else it failed
    ret = print_test_success(ret, test['success'])

    # Stop session daemon
    if dem_pid > 0:
        print PRINT_BRACKET + " Stopping session daemon (pid: %d)..." % (dem_pid)
        try:
            os.kill(dem_pid, SIGTERM)
            # This call simply does not work... It seems python does not relay the signal
            # to the child processes of sdaemon_proc.
            # sdaemon_proc.terminate()
            if ret != 0:
                print sdaemon_proc.communicate()[1]
            elif sdaemon_proc.returncode == None:
                sdaemon_proc.communicate()
        except OSError, e:
            print e

    # Make sure all thread are released
    if not no_stats:
        tw.join()
        sw_cpu.join()
        sw_mem.join()

    return ret

def main():
    for test in Tests:
        if not test['enabled']:
            continue

        ret = run_test(test)
        if ret != 0:
            # Stop all tests, the last one failed
            return
        print ""

def cleanup(signo, stack):
    """ Cleanup function """
    sys.exit(0)

if __name__ == "__main__":
    if not os.getuid() == 0:
        is_root = 0
        print "NOTICE: Not root. No kernel tracing will be tested\n"

    if os.path.isfile("test_list.py"):
        from test_list import Tests
    else:
        print "No test_list.py found. Stopping"
        cleanup(0, 0)

    TESTDIR_PATH = os.getcwd()

    if len(sys.argv) > 1:
        if sys.argv[1] == "--no-stats":
            no_stats = 1

    try:
        signal(SIGTERM, cleanup)
        signal(SIGINT, cleanup)
        main()
        cleanup(0, 0)
    except KeyboardInterrupt:
        cleanup(0, 0)
