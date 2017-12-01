EXTRA_DIST = foobar_provider.d
BUILT_SOURCES = foobar_provider.h

noinst_PROGRAMS = userspace-probe-sdt-binary
userspace_probe_sdt_binary_SOURCES = foobar_provider.h userspace-probe-sdt-binary.c sema.h sema.c
userspace_probe_sdt_binary_LDADD = foobar_provider.o libfoo.la libbar.la -ldl
nodist_userspace_probe_sdt_binary_SOURCES = foobar_provider.h

noinst_LTLIBRARIES = libfoo.la libbar.la libzzz.la
libfoo_la_SOURCES = foobar_provider.h libfoo.h libfoo.c
libfoo_la_LIBADD = foobar_provider.o
libfoo_la_LDFLAGS = -module -shared -avoid-version -rpath $(abs_builddir)/.libs/
nodist_libfoo_la_SOURCES = foobar_provider.h

libbar_la_SOURCES = foobar_provider.h libbar.h libbar.c
libbar_la_LIBADD = foobar_provider.o
libbar_la_LDFLAGS = -module -shared -avoid-version -rpath $(abs_builddir)/.libs/
nodist_libbar_la_SOURCES = foobar_provider.h

libzzz_la_SOURCES = foobar_provider.h libzzz.h libzzz.c
libzzz_la_LIBADD = foobar_provider.o
libzzz_la_LDFLAGS = -module -shared -avoid-version -rpath $(abs_builddir)/.libs/
nodist_libzzz_la_SOURCES = foobar_provider.h

foobar_provider.h: foobar_provider.d
	dtrace -s $< -o $@ -h

foobar_provider.o: foobar_provider.d
	dtrace -s $< -o $@ -G

CLEANFILES = foobar_provider.h
