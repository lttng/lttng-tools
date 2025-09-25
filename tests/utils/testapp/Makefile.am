# SPDX-License-Identifier: GPL-2.0-only

AM_CPPFLAGS += -I$(top_srcdir)/tests/utils \
	-I$(top_srcdir)/tests/utils/testapp

# Disable some warnings flags to accomodate the tracepoint headers
WARN_FLAGS = \
	-Wno-redundant-decls \
	-Wno-missing-field-initializers

AM_CFLAGS += $(WARN_FLAGS)
AM_CXXFLAGS += $(WARN_FLAGS)

LIB_LTTNG_CTL = $(top_builddir)/src/lib/lttng-ctl/liblttng-ctl.la

CLEANFILES =
EXTRA_DIST =

SUBDIRS = \
	  gen-ust-events-constructor

noinst_PROGRAMS =
noinst_LTLIBRARIES =
noinst_SCRIPTS = gen-py-events.py
noinst_HEADERS = signal-helper.hpp

if HAVE_LIBLTTNG_UST_CTL
noinst_PROGRAMS += gen-data-pending
gen_data_pending_SOURCES = gen-data-pending.cpp
gen_data_pending_LDADD = $(LIB_LTTNG_CTL) \
	$(top_builddir)/src/vendor/fmt/libfmt.la

noinst_PROGRAMS += gen-ust-events
gen_ust_events_SOURCES = \
	gen-ust-events.cpp \
	gen-ust-events-tp.c \
	gen-ust-events-tp.h
gen_ust_events_LDADD = $(UST_LIBS) $(DL_LIBS) \
		$(top_builddir)/tests/utils/libtestutils.la

noinst_PROGRAMS += gen-ust-nevents
gen_ust_nevents_SOURCES = \
	gen-ust-nevents.cpp \
	gen-ust-nevents-tp.c \
	gen-ust-nevents-tp.h
gen_ust_nevents_LDADD = $(UST_LIBS) $(DL_LIBS) \
		$(top_builddir)/tests/utils/libtestutils.la

noinst_PROGRAMS += gen-ust-tracef
gen_ust_tracef_SOURCES = gen-ust-tracef.cpp
gen_ust_tracef_LDADD = $(UST_LIBS) $(DL_LIBS)

noinst_PROGRAMS += gen-ust-nevents-str
gen_ust_nevents_str_SOURCES = \
	gen-ust-nevents-str.cpp \
	gen-ust-nevents-str-tp.c \
	gen-ust-nevents-str-tp.h
gen_ust_nevents_str_LDADD = $(UST_LIBS) $(DL_LIBS) \
		$(top_builddir)/tests/utils/libtestutils.la
endif

noinst_PROGRAMS += gen-kernel-test-events
gen_kernel_test_events_SOURCES = gen-kernel-test-events.c
gen_kernel_test_events_LDADD = $(top_builddir)/tests/utils/libtestutils.la

noinst_PROGRAMS += gen-syscall-events
gen_syscall_events_SOURCES = gen-syscall-events.cpp
gen_syscall_events_LDADD = $(top_builddir)/tests/utils/libtestutils.la


if HAVE_MODULES_USERSPACE_CALLSTACK_CONTEXT
noinst_PROGRAMS += gen-syscall-events-callstack
gen_syscall_events_callstack_SOURCES = gen-syscall-events-callstack.c
gen_syscall_events_callstack_LDADD = $(top_builddir)/tests/utils/libtestutils.la
gen_syscall_events_callstack_CFLAGS = -fno-omit-frame-pointer -mno-omit-leaf-frame-pointer \
				      $(AM_CFLAGS)

if LINKER_HAVE_NO_PIE_OPTION
#  The feature called Position Independent Execution (PIE) may be enabled by
#  default on some systems. Supporting this feature for this testapp would
#  increase the complexity of the testcases using this testapp as it would make
#  the addresses of functions unpredictable. So we prevent the linker from
#  using it by using the -no-pie option. If the -no-pie option is not
#  available, we assume that the PIE is not enabled by default so we do not
#  need to disable it.
gen_syscall_events_callstack_LDFLAGS = $(AM_LDFLAGS) -no-pie
endif # LINKER_HAVE_NO_PIE_OPTION
endif # HAVE_MODULES_USERSPACE_CALLSTACK_CONTEXT

# Testapps related to Linux namespaces
if IS_LINUX
noinst_PROGRAMS += gen-ns-events
gen_ns_events_SOURCES = gen-ns-events.cpp
gen_ns_events_CPPFLAGS = $(POPT_CFLAGS) $(AM_CPPFLAGS)
gen_ns_events_LDADD = \
		$(top_builddir)/tests/utils/libtestutils.la \
		$(DL_LIBS) $(POPT_LIBS)

if HAVE_LIBLTTNG_UST_CTL
noinst_PROGRAMS += gen-ust-events-ns
gen_ust_events_ns_SOURCES = \
	gen-ust-events-ns.cpp \
	gen-ust-events-ns-tp.c \
	gen-ust-events-ns-tp.h
gen_ust_events_ns_CPPFLAGS = $(POPT_CFLAGS) $(AM_CPPFLAGS)
gen_ust_events_ns_LDADD = $(UST_LIBS) -llttng-ust-fork \
		$(top_builddir)/tests/utils/libtestutils.la \
		$(DL_LIBS) $(POPT_LIBS)
endif # HAVE_LIBLTTNG_UST_CTL
endif # IS_LINUX




noinst_LTLIBRARIES += libdynsym.la
libdynsym_la_SOURCES = libdynsym.c libdynsym.h
libdynsym_la_LDFLAGS = -shared -module -avoid-version -rpath $(libdir)
libdynsym_la_CFLAGS = $(AM_CFLAGS) -O0

# Strip the library
libdynsym.strip-stamp: libdynsym.la
	@$(OBJCOPY) --strip-all .libs/libdynsym.so && touch $@

CLEANFILES += libdynsym.strip-stamp

noinst_PROGRAMS += userspace-probe-elf-binary
userspace_probe_elf_binary_SOURCES = userspace-probe-elf-binary.c
userspace_probe_elf_binary_CFLAGS = $(AM_CFLAGS) -O0
userspace_probe_elf_binary_LDADD = libdynsym.la

noinst_PROGRAMS += userspace-probe-elf-cxx-binary
userspace_probe_elf_cxx_binary_SOURCES = userspace-probe-elf-cxx-binary.cpp test_class.cpp test_class.hpp
userspace_probe_elf_cxx_binary_CFLAGS = $(AM_CFLAGS) -O0

if TEST_SDT_UPROBE
BUILT_SOURCES = foobar_provider.h
CLEANFILES += foobar_provider.h
EXTRA_DIST += foobar_provider.d

noinst_PROGRAMS += userspace-probe-sdt-binary
userspace_probe_sdt_binary_SOURCES = userspace-probe-sdt-binary.c sema.h sema.c
userspace_probe_sdt_binary_LDADD = foobar_provider.o libfoo.la libbar.la $(DL_LIBS)
# Add the build directory since foobar_provider.h is generated at build time
userspace_probe_sdt_binary_CFLAGS = $(AM_CFLAGS) \
		-I$(top_builddir)/tests/utils/testapp

noinst_LTLIBRARIES += libfoo.la libbar.la libzzz.la
libfoo_la_SOURCES = libfoo.h libfoo.c
libfoo_la_LIBADD = foobar_provider.o
libfoo_la_LDFLAGS = -module -shared -avoid-version -rpath $(libdir)
# Add the build directory since foobar_provider.h is generated at build time
libfoo_la_CFLAGS = $(AM_CFLAGS) \
		-I$(top_builddir)/tests/utils/testapp

libbar_la_SOURCES = libbar.h libbar.c
libbar_la_LIBADD = foobar_provider.o
libbar_la_LDFLAGS = -module -shared -avoid-version -rpath $(libdir)
# Add the build directory since foobar_provider.h is generated at build time
libbar_la_CFLAGS = $(AM_CFLAGS) \
		-I$(top_builddir)/tests/utils/testapp

libzzz_la_SOURCES = libzzz.h libzzz.c
libzzz_la_LIBADD = foobar_provider.o
libzzz_la_LDFLAGS = -module -shared -avoid-version -rpath $(libdir)
# Add the build directory since foobar_provider.h is generated at build time
libzzz_la_CFLAGS = $(AM_CFLAGS) \
		-I$(top_builddir)/tests/utils/testapp

dtrace_verbose = $(dtrace_verbose_@AM_V@)
dtrace_verbose_ = $(dtrace_verbose_@AM_DEFAULT_V@)
dtrace_verbose_0 = @echo "  DTRACE  " $@;

foobar_provider.h: foobar_provider.d
	$(dtrace_verbose)$(DTRACE) -s $< -o $@ -h

foobar_provider.o: foobar_provider.d
	$(dtrace_verbose)$(DTRACE) -s $< -o $@ -G

endif # TEST_SDT_UPROBE


TEST_DEPS = gen-py-events.py
EXTRA_DIST += gen-py-events.py

all-local: libdynsym.strip-stamp
	@if [ x"$(srcdir)" != x"$(builddir)" ]; then \
		for script in $(TEST_DEPS); do \
			cp -f $(srcdir)/$$script $(builddir); \
		done; \
	fi

clean-local:
	@if [ x"$(srcdir)" != x"$(builddir)" ]; then \
		for script in $(TEST_DEPS); do \
			rm -f $(builddir)/$$script; \
		done; \
	fi
