LTTng&#8209;tools
=================

[![Jenkins](https://img.shields.io/jenkins/s/https/ci.lttng.org/lttng-tools_master_build.svg)](https://ci.lttng.org/job/lttng-tools_master_build/)
[![Coverity](https://img.shields.io/coverity/scan/lttng-tools.svg)](https://scan.coverity.com/projects/lttng-tools)

_**LTTng&#8209;tools**_ is a set of components to control
[LTTng](https://lttng.org/) tracing.

The project includes:

* The LTTng [session daemon](https://lttng.org/man/8/lttng-sessiond/).
* The LTTng consumer daemon.
* The LTTng [relay daemon](https://lttng.org/man/8/lttng-relayd/).
* liblttng&#8209;ctl, a library with a C&nbsp;API used to communicate
  with the session daemon.
* Python&nbsp;3 bindings of liblttng&#8209;ctl.
* [`lttng`](https://lttng.org/man/1/lttng/),
  a command-line tool over liblttng&#8209;ctl.
* [`lttng-crash`](https://lttng.org/man/1/lttng-crash/), a command-line
  tool to recover and view LTTng&nbsp;2 trace buffers in the event of
  a crash.

Required and optional dependencies
----------------------------------
You need the following dependencies to build and run the
LTTng&#8209;tools components:

* **Linux kernel&nbsp;≥&nbsp;2.6.27**

  Use `--disable-epoll` at [build configuration](#configure) time to
  build LTTng&#8209;tools for an older kernel. However, note that we
  can't provide any guarantee below 2.6.27.

* **[Userspace&nbsp;RCU](http://www.liburcu.org/) ≥ 0.9.0**.

  Debian/Ubuntu package: `liburcu-dev`.

* **popt&nbsp;≥&nbsp;1.13**

  Debian/Ubuntu package: `libpopt-dev`.

* **[Libxml2](http://xmlsoft.org/)&nbsp;≥&nbsp;2.7.6**

  Debian/Ubuntu package: `libxml2-dev`

The following dependencies are optional:

* **[Babeltrace&nbsp;2](https://babeltrace.org/)**: default viewer
  of the [`lttng view`](https://lttng.org/man/1/lttng-view/)
  command.

  Debian/Ubuntu package: `babeltrace2`

* **[LTTng&#8209;UST](https://lttng.org/)** (same minor version as
  LTTng&#8209;tools):
  LTTng user space tracing (applications and libraries).

  Debian/Ubuntu package: `liblttng-ust-dev`

* **Perl**: `make check` and tests.

* **[Python](https://www.python.org/)&nbsp;≥&nbsp;3.0**:
  `make check` and tests.

  Debian/Ubuntu package: `python3`

* **[SWIG](http://www.swig.org/)&nbsp;≥&nbsp;2.0** and
  **Python&nbsp;3 development headers**: Python bindings
  (enabled at [build configuration](#configure) time with the
  `--enable-python-bindings` option).

  Debian/Ubuntu packages: `swig2.0` and `python3-dev`

* **modprobe** and/or
  **[kmod](https://git.kernel.org/pub/scm/utils/kernel/kmod/kmod.git/)&nbsp;≥&nbsp;22**:
  automatic LTTng kernel modules loading (kernel tracing).

* **Bash**: `make check`.

* **[`man`](http://man7.org/linux/man-pages/man1/man.1.html)**
  (manual pager): view `lttng` command manual
  pages with the `--help` option or with the
  [`lttng help`](https://lttng.org/man/1/lttng-help/) command.

  Note that you can use the [build configuration](#configure) option
  `--enable-embedded-help` to embed the manual pages into the
  `lttng`, `lttng-sessiond`, `lttng-relayd`, and `lttng-crash` programs
  so that you don't need `man` to view them.

* **[libpfm](http://perfmon2.sourceforge.net/)&nbsp;≥&nbsp;4.0**:
  perf regression test suite.

  Debian/Ubuntu package: `libpfm4-dev`

LTTng&#8209;tools supports both the LTTng Linux kernel tracer and LTTng
user space tracer sharing the same _minor_ version. While some minor
releases do not change the tracer ABIs and _could_ work, no testing is
performed to ensure that cross-version compatibility is maintained.

You don't need to rebuild or modify applications instrumented with older
versions of the LTTng&#8209;UST project to make them work with the
components of the latest LTTng&#8209;tools release.

See the [LTTng Documentation](https://lttng.org/docs/) for more
information on versioning.

Build from source
-----------------
### Dependencies

You need the following tools to build LTTng&#8209;tools:

* **[GNU&nbsp;Autotools](https://www.gnu.org/software/automake/manual/html_node/Autotools-Introduction.html)**
  (**Automake&nbsp;≥&nbsp;1.10**,
  **Autoconf&nbsp;≥&nbsp;2.64**, and **Autoheader&nbsp;≥&nbsp;2.50**)

* **[GNU&nbsp;Libtool](http://www.gnu.org/software/autoconf/)&nbsp;≥&nbsp;2.2**

* **[Flex](https://github.com/westes/flex/)&nbsp;≥&nbsp;2.5.35**

* **[Bison](https://www.gnu.org/software/bison/)&nbsp;≥&nbsp;2.4**

To build the LTTng&#8209;tools manual pages:

* **[AsciiDoc](https://www.methods.co.nz/asciidoc/)&nbsp;≥&nbsp;8.4.5**

  Previous versions could work, but were not tested.

* **[xmlto](https://pagure.io/xmlto)&nbsp;≥&nbsp;0.0.21**

  Previous versions could work, but were not tested.

If you use GNU&nbsp;gold, which is _not_ mandatory:

* **GNU&nbsp;gold&nbsp;≥&nbsp;2.22**

Note that with GNU&nbsp;gold, you might have to add
`-L/usr/local/lib` to the `LDFLAGS` environment variable.

### Build steps

1. **If you have the LTTng&#8209;tools Git source**, run:

       $ ./bootstrap

   This script creates the `configure` script.

2. <span id="configure"></span>Configure the build:

       $ ./configure

   If you want the liblttng&#8209;ctl Python bindings, use the
   `--enable-python-bindings` option. See also the
   `PYTHON` and `PYTHON_CONFIG` environment variables in
   `./configure --help`.

   If you don't want to build the manual pages, use the
   `--disable-man-pages` option.

   If you want to embed the manual pages into the
   `lttng`, `lttng-sessiond`, `lttng-relayd`, and `lttng-crash` programs
   so that you don't need `man` to view them, use the
   `--enable-embedded-help` option.

   If your Linux kernel is older than 2.6.27, use the
   `--enable-epoll` option.

   This build configuration script finds LTTng&#8209;UST with
   [pkg&#8209;config](https://www.freedesktop.org/wiki/Software/pkg-config/):
   set the `PKG_CONFIG_PATH` environment variable accordingly if
   pkg&#8209;config cannot find the `lttng-ust` package information.

   See `./configure --help` for the complete list of options.

3. Build the project:

       $ make

4. Install the project:

       $ sudo make install
       $ sudo ldconfig

Usage
-----
See the [Tracing control](https://lttng.org/docs/#doc-controlling-tracing)
section of the LTTng Documentation to learn how to use the
LTTng&#8209;tools components.

See also the [LTTng manual pages](https://lttng.org/man/) (all
section&nbsp;1 and&nbsp;8 pages).

As there's no official liblttng&#8209;ctl Python bindings yet, see
[`doc/python-howto.txt`](doc/python-howto.txt) to understand how to
use them.

Community
---------
* **Mailing list**:
  [lttng&#8209;dev](https://lists.lttng.org/cgi-bin/mailman/listinfo).

* **IRC channel**:
  [`#lttng`](irc://irc.oftc.net/lttng) on the OFTC network.

* **Bug tracker**::
  [LTTng&#8209;tools bug tracker](https://bugs.lttng.org/projects/lttng-tools/).

* **GitHub project**:
  [lttng/lttng&#8209;tools](https://github.com/lttng/lttng-tools/).

* **Continuous integration**:
  [LTTng CI](https://ci.lttng.org/).

* **Code review**:
  [_lttng&#8209;tools_ project](https://review.lttng.org/q/project:lttng-tools)
  on LTTng Review.
