LTTng-tools
===========

[![Jenkins](https://img.shields.io/jenkins/s/https/ci.lttng.org/lttng-tools_master_build.svg)](https://ci.lttng.org/job/lttng-tools_master_build/)
[![Coverity](https://img.shields.io/coverity/scan/lttng-tools.svg)](https://scan.coverity.com/projects/lttng-tools)

LTTng-tools is a set of tools to control [LTTng](https://lttng.org/)
tracing. The project includes the LTTng session daemon, consumer daemon
and relay daemon, as well as `liblttng-ctl`, a C library used to
communicate with the session daemon, and `lttng`, a command line
interface to `liblttng-ctl`.


Requirements and optional dependencies
--------------------------------------

The following items are _required_ to build and run LTTng-tools
components:

  - **Linux kernel >= 2.6.27**: for `epoll()` support, at least this
    version is needed. However, `poll()` is also supported by
    configuring LTTng-tools with the `--disable-epoll` option. Using
    that, the kernel version may probably be older, but we can't provide
    any guarantee. Please let us know if you are able to go lower
    without any problems.
  - **[`liburcu`](http://www.liburcu.org/) >= 0.9.0**: userspace RCU library,
    by Mathieu Desnoyers and Paul E. McKenney.
  - **`libpopt` >= 1.13**:  command line arguments parsing library.
    - Debian/Ubuntu package: `libpopt-dev`
  - **`libuuid`**: universally unique ID library
    - Debian/Ubuntu package: `uuid-dev`
  - **`libxml2` >= 2.7.6**:  XML document parsing library. Needed for
    tracing session configuration saving/loading and machine interface
    output support.
    - Debian/Ubuntu package: `libxml2-dev`


The following items are _optional_ dependencies:

  - **[Babeltrace](https://lttng.org/babeltrace)**: trace viewer.
    Enables the use of `lttng view` command.
    - Debian/Ubuntu package: `babeltrace`
  - **[LTTng UST](https://lttng.org) (same minor version as LTTng Tools)**:
    userspace tracer. Enables the tracing of userspace applications.
    - Debian/Ubuntu package: `liblttng-ust-dev`
  - **Perl**: needed for `make check` and tests.
  - **Python >= 3.0**: needed for `make check` and tests.
    - Debian/Ubuntu package: `python3`
  - **SWIG >= 2.0** and **Python 3 development headers**: needed for
    Python bindings
    (enabled at configure time with the `--enable-python-bindings` option).
    - Debian/Ubuntu packages: `swig2.0` and `python3-dev`
  - **modprobe**: needed for automatic LTTng kernel modules loading
    (kernel tracing).
  - **bash**: needed to run `make check`.
  - **man** (manual pager): needed to view LTTng-tools commands' man
    pages with the `--help` option or with the `lttng help` command.
    Note that without `man`, you cannot get offline help with
    LTTng-tools commands, not even their usage.
  - **libpfm >= 4.0**: needed to run the perf regression test suite.
    - Debian/Ubuntu package: `libpfm4-dev`

LTTng-tools supports both the [LTTng Linux Kernel tracer](https://lttng.org)
and [LTTng user space tracer](https://lttng.org) released as part of the same
**minor** release series. While some releases do not change the tracer ABIs and
should work with, no testing is performed to ensure cross-version compatibility
is maintained.

Note that applications instrumented with older versions of the LTTng UST project
do not have to be rebuilt or modified to work with the latest LTTng-tools.
For more information on versioning, please refer to the
[LTTng documentation](https://lttng.org/docs).

Building
--------

This source tree is based on the Autotools suite from GNU to simplify
portability. Here are some things you should have on your system in
order to compile the Git repository tree:

  - **GNU Autotools** (**Automake >= 1.10**, **Autoconf >= 2.64**,
    **Autoheader >= 2.50**; make sure your system-wide `automake` points
    to a recent version)
  - **[GNU Libtool](http://www.gnu.org/software/autoconf/) >= 2.2**
  - **Flex >= 2.5.35**
  - **Bison >= 2.4**

Optional packages to build LTTng-tools man pages:

  - **AsciiDoc >= 8.4.5** (previous versions may work, but were
    not tested)
  - **xmlto >= 0.0.21** (previous versions may work, but were
    not tested)

If you use GNU gold, which is _not_ mandatory, make sure you have this
version:

  - **GNU gold >= 2.22**

Before this version of GNU gold, we hit a
[known bug](http://sourceware.org/bugzilla/show_bug.cgi?id=11317).
Be advised that with GNU gold, you might have to specify
`-L/usr/local/lib` in `LDFLAGS`.

If you get the tree from the Git repository, you will need to run

    ./bootstrap

in its root. It calls all the GNU tools needed to prepare the tree
configuration.

To build LTTng-tools, do:

    ./configure
    make
    sudo make install
    sudo ldconfig

If you want Python bindings, add the `--enable-python-bindings` option
to `configure`. Please note that some distributions will need the
following environment variables set before running configure:

    export PYTHON="python3"
    export PYTHON_CONFIG="/usr/bin/python3-config"


Using
-----

Please see [`doc/quickstart.txt`](doc/quickstart.txt) to get started
with LTTng tracing. You can also use the `-h` or `--help` option of
any `lttng` command, e.g.:

    lttng enable-event --help

A network streaming HOWTO can be found in
[`doc/streaming-howto.txt`](doc/streaming-howto.txt) which quickly
helps you understand how to stream a LTTng 2.x trace.

A Python binding HOWTO can be found in
[`doc/python-howto.txt`](doc/python-howto.txt) which quickly helps you
understand how to use the Python module to control LTTng.


Contact
-------

Maintainer: [Jérémie Galarneau](mailto:jeremie.galarneau@efficios.com)

Mailing list: [`lttng-dev@lists.lttng.org`](https://lttng.org/cgi-bin/mailman/listinfo/lttng-dev)


Package contents
----------------

This package contains the following elements:

  - `doc`: LTTng-tools documentation.
  - `include`: the public header files that will be installed on the system.
  - `src/bin`: source code of LTTng-tools programs.
    - `lttng-consumerd`: consumer daemon.
    - `lttng-crash`: crash trace viewer.
    - `lttng-relayd`: relay daemon.
    - `lttng-sessiond`: session daemon.
    - `lttng`: command line interface for LTTng tracing control.
  - `src/common`: common LTTng-tools source code.
    - `compat`: compatibility library mostly for FreeBSD and Linux.
    - `config`: tracing session configuration saving/loading.
    - `hashtable`: library wrapper over Userspace RCU hashtables.
    - `health`: health check subsytem.
    - `index`: CTF index utilities.
    - `kernel-consumer`: Linux kernel consumer.
    - `kernel-ctl`: Linux kernel tracer control.
    - `relayd`: relay daemon control.
    - `sessiond-comm`: session daemon communication.
    - `ust-consumer`: user space consumer.
  - `src/lib`: source code of LTTng-tools libraries.
    - `lttng-ctl`: LTTng control library.
  - `tests`: various test programs.
