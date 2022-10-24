# SPDX-License-Identifier: GPL-2.0-only

EXTRA_DIST = foobar_provider.d

# Although this is redundant with the check performed in the parent
# Makefile.am, this is needed for autotools v1.16+ as BUILT_SOURCES is
# evaluated for the 'dist' target.
#
# It is fine to generate this header in the 'dist' target (when
# enabled) as it won't be distributed anyhow (it is marked as nodist).
if TEST_SDT_UPROBE
BUILT_SOURCES = foobar_provider.h
endif

noinst_PROGRAMS = userspace-probe-sdt-binary
userspace_probe_sdt_binary_SOURCES = userspace-probe-sdt-binary.c sema.h sema.c
userspace_probe_sdt_binary_LDADD = foobar_provider.o libfoo.la libbar.la $(DL_LIBS)
userspace_probe_sdt_binary_CFLAGS = -I$(abs_builddir)
nodist_userspace_probe_sdt_binary_SOURCES = $(abs_builddir)/foobar_provider.h

noinst_LTLIBRARIES = libfoo.la libbar.la libzzz.la
libfoo_la_SOURCES = libfoo.h libfoo.c
libfoo_la_LIBADD = foobar_provider.o
libfoo_la_CFLAGS = -I$(abs_builddir)
libfoo_la_LDFLAGS = -module -shared -avoid-version -rpath $(libdir)
nodist_libfoo_la_SOURCES = $(abs_builddir)/foobar_provider.h

libbar_la_SOURCES = libbar.h libbar.c
libbar_la_LIBADD = foobar_provider.o
libbar_la_CFLAGS = -I$(abs_builddir)
libbar_la_LDFLAGS = -module -shared -avoid-version -rpath $(libdir)
nodist_libbar_la_SOURCES = $(abs_builddir)/foobar_provider.h

libzzz_la_SOURCES = libzzz.h libzzz.c
libzzz_la_LIBADD = foobar_provider.o
libzzz_la_CFLAGS = -I$(abs_builddir)
libzzz_la_LDFLAGS = -module -shared -avoid-version -rpath $(libdir)
nodist_libzzz_la_SOURCES = $(abs_builddir)/foobar_provider.h

dtrace_verbose = $(dtrace_verbose_@AM_V@)
dtrace_verbose_ = $(dtrace_verbose_@AM_DEFAULT_V@)
dtrace_verbose_0 = @echo "  DTRACE  " $@;

foobar_provider.h: foobar_provider.d
	$(dtrace_verbose)$(DTRACE) -s $< -o $@ -h

foobar_provider.o: foobar_provider.d
	$(dtrace_verbose)$(DTRACE) -s $< -o $@ -G

CLEANFILES = foobar_provider.h
