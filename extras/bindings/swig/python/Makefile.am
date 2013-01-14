lttng.i: lttng.i.in
	sed "s/LTTNG_VERSION_STR/LTTng $(PACKAGE_VERSION)/g" <lttng.i.in >lttng.i

AM_CFLAGS = -I$(PYTHON_INCLUDE) -I$(top_srcdir)/lib/lttng-ctl -I../common \
              $(BUDDY_CFLAGS)

EXTRA_DIST = lttng.i
python_PYTHON = lttng.py
pyexec_LTLIBRARIES = _lttng.la

MAINTAINERCLEANFILES = lttng_wrap.c lttng.py

_lttng_la_SOURCES = lttng_wrap.c

_lttng_la_LDFLAGS = -module

_lttng_la_LIBADD = 	$(top_srcdir)/src/lib/lttng-ctl/liblttng-ctl.la 		\
			$(top_srcdir)/src/common/sessiond-comm/libsessiond-comm.la

# SWIG 'warning md variable unused' fixed after SWIG build:
lttng_wrap.c: lttng.i
	$(SWIG) -python -I. -I$(top_srcdir)/src/common/sessiond-comm lttng.i
	sed -i "s/PyObject \*m, \*d, \*md;/PyObject \*m, \*d;\n#if defined(SWIGPYTHON_BUILTIN)\nPyObject *md;\n#endif/g" lttng_wrap.c
	sed -i "s/md = d/d/g" lttng_wrap.c
	sed -i "s/(void)public_symbol;/(void)public_symbol;\n  md = d;/g" lttng_wrap.c

CLEANFILES = lttng.i lttng.py lttng_wrap.c lttng.pyc
