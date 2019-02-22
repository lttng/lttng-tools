noinst_SCRIPTS = test_multi_lib
EXTRA_DIST = test_multi_lib
noinst_PROGRAMS = exec-with-callsites exec-without-callsites

exec_with_callsites_SOURCES = multi-lib-test.c callsites.c
exec_with_callsites_LDFLAGS = -ldl $(POPT_LIBS)
exec_with_callsites_CFLAGS = $(POPT_CFLAGS) $(AM_CFLAGS) -DHAS_CALLSITES=1

exec_without_callsites_SOURCES = multi-lib-test.c
exec_without_callsites_LDFLAGS = -ldl $(POPT_LIBS) -llttng-ust
exec_without_callsites_LDADD = probes.o
exec_without_callsites_CFLAGS = $(POPT_CFLAGS) $(AM_CFLAGS) -DHAS_CALLSITES=0

PROBES_SRC=probes.c probes.h
PROBES_LDF=-shared -module -llttng-ust -avoid-version -rpath $(abs_builddir)/.libs/
PROBES_CF=$(AM_CFLAGS) $(AM_CPPFLAGS) $(CFLAGS) $(CPPFLAGS) -c -I$(srcdir)/

probes.o: probes.c probes.h
	$(CC) $(PROBES_CF) -o $@ $<

noinst_LTLIBRARIES = libprobes_a.la libprobes_a_prime.la \
			libprobes_b.la libprobes_c.la libprobes_c_prime.la \
			libprobes_d.la libprobes_e.la libprobes_f.la \
			libprobes_g.la libprobes_h.la libprobes_i.la \
			libprobes_j.la libprobes_k.la libprobes_l.la \
			libprobes_m.la libprobes_n.la libprobes_o.la \
			libprobes_p.la

noinst_LTLIBRARIES += libcallsites_1.la libcallsites_2.la

CALLSITES_SRC=callsites.c callsites.h
CALLSITES_LDF=-shared -module -llttng-ust -avoid-version -rpath $(abs_builddir)/.libs/
CALLSITES_CF=-c -I.

libprobes_a_la_SOURCES = $(PROBES_SRC)
libprobes_a_la_LDFLAGS = $(PROBES_LDF)
libprobes_a_la_CFLAGS = $(AM_CFLAGS) $(PROBES_CF) -DACTIVATE_PROBES_A

libprobes_a_prime_la_SOURCES = $(PROBES_SRC)
libprobes_a_prime_la_LDFLAGS = $(PROBES_LDF)
libprobes_a_prime_la_CFLAGS = $(AM_CFLAGS) $(PROBES_CF) -DACTIVATE_PROBES_A

libprobes_b_la_SOURCES = $(PROBES_SRC)
libprobes_b_la_LDFLAGS = $(PROBES_LDF)
libprobes_b_la_CFLAGS = $(AM_CFLAGS) $(PROBES_CF) -DACTIVATE_PROBES_B

libprobes_c_la_SOURCES = $(PROBES_SRC)
libprobes_c_la_LDFLAGS = $(PROBES_LDF)
libprobes_c_la_CFLAGS = $(AM_CFLAGS) $(PROBES_CF) -DACTIVATE_PROBES_C

libprobes_c_prime_la_SOURCES = $(PROBES_SRC)
libprobes_c_prime_la_LDFLAGS = $(PROBES_LDF)
libprobes_c_prime_la_CFLAGS = $(AM_CFLAGS) $(PROBES_CF) -DACTIVATE_PROBES_C

libprobes_d_la_SOURCES = $(PROBES_SRC)
libprobes_d_la_LDFLAGS = $(PROBES_LDF)
libprobes_d_la_CFLAGS = $(AM_CFLAGS) $(PROBES_CF) -DACTIVATE_PROBES_D

libprobes_e_la_SOURCES = $(PROBES_SRC)
libprobes_e_la_LDFLAGS = $(PROBES_LDF)
libprobes_e_la_CFLAGS = $(AM_CFLAGS) $(PROBES_CF) -DACTIVATE_PROBES_E

libprobes_f_la_SOURCES = $(PROBES_SRC)
libprobes_f_la_LDFLAGS = $(PROBES_LDF)
libprobes_f_la_CFLAGS = $(AM_CFLAGS) $(PROBES_CF) -DACTIVATE_PROBES_F

libprobes_g_la_SOURCES = $(PROBES_SRC)
libprobes_g_la_LDFLAGS = $(PROBES_LDF)
libprobes_g_la_CFLAGS = $(AM_CFLAGS) $(PROBES_CF) -DACTIVATE_PROBES_G

libprobes_h_la_SOURCES = $(PROBES_SRC)
libprobes_h_la_LDFLAGS = $(PROBES_LDF)
libprobes_h_la_CFLAGS = $(AM_CFLAGS) $(PROBES_CF) -DACTIVATE_PROBES_H

libprobes_i_la_SOURCES = $(PROBES_SRC)
libprobes_i_la_LDFLAGS = $(PROBES_LDF)
libprobes_i_la_CFLAGS = $(AM_CFLAGS) $(PROBES_CF) -DACTIVATE_PROBES_I

libprobes_j_la_SOURCES = $(PROBES_SRC)
libprobes_j_la_LDFLAGS = $(PROBES_LDF)
libprobes_j_la_CFLAGS = $(AM_CFLAGS) $(PROBES_CF) -DACTIVATE_PROBES_J

libprobes_k_la_SOURCES = $(PROBES_SRC)
libprobes_k_la_LDFLAGS = $(PROBES_LDF)
libprobes_k_la_CFLAGS = $(AM_CFLAGS) $(PROBES_CF) -DACTIVATE_PROBES_K

libprobes_l_la_SOURCES = $(PROBES_SRC)
libprobes_l_la_LDFLAGS = $(PROBES_LDF)
libprobes_l_la_CFLAGS = $(AM_CFLAGS) $(PROBES_CF) -DACTIVATE_PROBES_L

libprobes_m_la_SOURCES = $(PROBES_SRC)
libprobes_m_la_LDFLAGS = $(PROBES_LDF)
libprobes_m_la_CFLAGS = $(AM_CFLAGS) $(PROBES_CF) -DACTIVATE_PROBES_M

libprobes_n_la_SOURCES = $(PROBES_SRC)
libprobes_n_la_LDFLAGS = $(PROBES_LDF)
libprobes_n_la_CFLAGS = $(AM_CFLAGS) $(PROBES_CF) -DACTIVATE_PROBES_N

libprobes_o_la_SOURCES = $(PROBES_SRC)
libprobes_o_la_LDFLAGS = $(PROBES_LDF)
libprobes_o_la_CFLAGS = $(AM_CFLAGS) $(PROBES_CF) -DACTIVATE_PROBES_O

libprobes_p_la_SOURCES = $(PROBES_SRC)
libprobes_p_la_LDFLAGS = $(PROBES_LDF)
libprobes_p_la_CFLAGS = $(AM_CFLAGS) $(PROBES_CF) -DACTIVATE_PROBES_P

libcallsites_1_la_SOURCES = $(CALLSITES_SRC)
libcallsites_1_la_LDFLAGS = $(CALLSITES_LDF)
libcallsites_1_la_CFLAGS = $(AM_CFLAGS) $(CALLSITES_CF) -DVALUE=11111

libcallsites_2_la_SOURCES = $(CALLSITES_SRC)
libcallsites_2_la_LDFLAGS = $(CALLSITES_LDF)
libcallsites_2_la_CFLAGS = $(AM_CFLAGS) $(CALLSITES_CF) -DVALUE=22222

CLEANFILES=probes.o

all-local:
	@if [ x"$(srcdir)" != x"$(builddir)" ]; then \
		for script in $(EXTRA_DIST); do \
			cp -f $(srcdir)/$$script $(builddir); \
		done; \
	fi

clean-local:
	@if [ x"$(srcdir)" != x"$(builddir)" ]; then \
		for script in $(EXTRA_DIST); do \
			rm -f $(builddir)/$$script; \
		done; \
	fi
