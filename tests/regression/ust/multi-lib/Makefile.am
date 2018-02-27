noinst_SCRIPTS = test_multi_lib
noinst_PROGRAMS = exec-bare exec-callsites exec-probes

exec_callsites_SOURCES = multi-lib-test.c callsites.c
exec_callsites_LDFLAGS = -ldl -lpopt
exec_callsites_CFLAGS = -DCALLSITES

exec_probes_SOURCES = multi-lib-test.c
exec_probes_LDFLAGS = -ldl -lpopt -llttng-ust
exec_probes_LDADD = probes.o
exec_probes_CFLAGS = -DPROBES

exec_bare_SOURCES = multi-lib-test.c
exec_bare_LDFLAGS = -ldl -lpopt
exec_bare_CFLAGS = -DBARE

PROBES_SRC=probes.c probes.h
PROBES_LDF=-shared -module -llttng-ust -avoid-version -rpath $(abs_builddir)/.libs/
PROBES_CF=-c -I$(srcdir)/

probes.o: probes.c probes.h
	$(CC) $(PROBES_CF) -o $@ $<

noinst_LTLIBRARIES = libprobes_a.la libprobes_a_prime.la \
			libprobes_b.la libprobes_c.la libprobes_c_prime.la \
			libprobes_d.la libprobes_e.la libprobes_f.la \
			libprobes_g.la libprobes_h.la libprobes_i.la \
			libprobes_j.la libprobes_k.la libprobes_l.la \
			libprobes_m.la libprobes_n.la libprobes_o.la \
			libprobes_p.la

noinst_LTLIBRARIES += libcallsites_a.la libcallsites_b.la
noinst_LTLIBRARIES += libcallsites_probes_a.la libcallsites_probes_b.la

CALLSITES_SRC=callsites.c callsites.h
CALLSITES_LDF=-shared -module -llttng-ust -avoid-version -rpath $(abs_builddir)/.libs/
CALLSITES_CF=-c -I.

libprobes_a_la_SOURCES = $(PROBES_SRC)
libprobes_a_la_LDFLAGS = $(PROBES_LDF)
libprobes_a_la_CFLAGS = $(PROBES_CF) -DACTIVATE_PROBES_A

libprobes_a_prime_la_SOURCES = $(PROBES_SRC)
libprobes_a_prime_la_LDFLAGS = $(PROBES_LDF)
libprobes_a_prime_la_CFLAGS = $(PROBES_CF) -DACTIVATE_PROBES_A

libprobes_b_la_SOURCES = $(PROBES_SRC)
libprobes_b_la_LDFLAGS = $(PROBES_LDF)
libprobes_b_la_CFLAGS = $(PROBES_CF) -DACTIVATE_PROBES_B

libprobes_c_la_SOURCES = $(PROBES_SRC)
libprobes_c_la_LDFLAGS = $(PROBES_LDF)
libprobes_c_la_CFLAGS = $(PROBES_CF) -DACTIVATE_PROBES_C

libprobes_c_prime_la_SOURCES = $(PROBES_SRC)
libprobes_c_prime_la_LDFLAGS = $(PROBES_LDF)
libprobes_c_prime_la_CFLAGS = $(PROBES_CF) -DACTIVATE_PROBES_C

libprobes_d_la_SOURCES = $(PROBES_SRC)
libprobes_d_la_LDFLAGS = $(PROBES_LDF)
libprobes_d_la_CFLAGS = $(PROBES_CF) -DACTIVATE_PROBES_D

libprobes_e_la_SOURCES = $(PROBES_SRC)
libprobes_e_la_LDFLAGS = $(PROBES_LDF)
libprobes_e_la_CFLAGS = $(PROBES_CF) -DACTIVATE_PROBES_E

libprobes_f_la_SOURCES = $(PROBES_SRC)
libprobes_f_la_LDFLAGS = $(PROBES_LDF)
libprobes_f_la_CFLAGS = $(PROBES_CF) -DACTIVATE_PROBES_F

libprobes_g_la_SOURCES = $(PROBES_SRC)
libprobes_g_la_LDFLAGS = $(PROBES_LDF)
libprobes_g_la_CFLAGS = $(PROBES_CF) -DACTIVATE_PROBES_G

libprobes_h_la_SOURCES = $(PROBES_SRC)
libprobes_h_la_LDFLAGS = $(PROBES_LDF)
libprobes_h_la_CFLAGS = $(PROBES_CF) -DACTIVATE_PROBES_H

libprobes_i_la_SOURCES = $(PROBES_SRC)
libprobes_i_la_LDFLAGS = $(PROBES_LDF)
libprobes_i_la_CFLAGS = $(PROBES_CF) -DACTIVATE_PROBES_I

libprobes_j_la_SOURCES = $(PROBES_SRC)
libprobes_j_la_LDFLAGS = $(PROBES_LDF)
libprobes_j_la_CFLAGS = $(PROBES_CF) -DACTIVATE_PROBES_J

libprobes_k_la_SOURCES = $(PROBES_SRC)
libprobes_k_la_LDFLAGS = $(PROBES_LDF)
libprobes_k_la_CFLAGS = $(PROBES_CF) -DACTIVATE_PROBES_K

libprobes_l_la_SOURCES = $(PROBES_SRC)
libprobes_l_la_LDFLAGS = $(PROBES_LDF)
libprobes_l_la_CFLAGS = $(PROBES_CF) -DACTIVATE_PROBES_L

libprobes_m_la_SOURCES = $(PROBES_SRC)
libprobes_m_la_LDFLAGS = $(PROBES_LDF)
libprobes_m_la_CFLAGS = $(PROBES_CF) -DACTIVATE_PROBES_M

libprobes_n_la_SOURCES = $(PROBES_SRC)
libprobes_n_la_LDFLAGS = $(PROBES_LDF)
libprobes_n_la_CFLAGS = $(PROBES_CF) -DACTIVATE_PROBES_N

libprobes_o_la_SOURCES = $(PROBES_SRC)
libprobes_o_la_LDFLAGS = $(PROBES_LDF)
libprobes_o_la_CFLAGS = $(PROBES_CF) -DACTIVATE_PROBES_O

libprobes_p_la_SOURCES = $(PROBES_SRC)
libprobes_p_la_LDFLAGS = $(PROBES_LDF)
libprobes_p_la_CFLAGS = $(PROBES_CF) -DACTIVATE_PROBES_P

libcallsites_a_la_SOURCES = $(CALLSITES_SRC)
libcallsites_a_la_LDFLAGS = $(CALLSITES_LDF)
libcallsites_a_la_CFLAGS = $(CALLSITES_CF)

libcallsites_b_la_SOURCES = $(CALLSITES_SRC)
libcallsites_b_la_LDFLAGS = $(CALLSITES_LDF)
libcallsites_b_la_CFLAGS = $(CALLSITES_CF)

libcallsites_probes_a_la_SOURCES = $(CALLSITES_SRC) $(PROBES_SRC)
libcallsites_probes_a_la_LDFLAGS = $(CALLSITES_LDF)
libcallsites_probes_a_la_CFLAGS = $(CALLSITES_CF) -DACTIVATE_PROBES_A

libcallsites_probes_b_la_SOURCES = $(CALLSITES_SRC) $(PROBES_SRC)
libcallsites_probes_b_la_LDFLAGS = $(CALLSITES_LDF)
libcallsites_probes_b_la_CFLAGS = $(CALLSITES_CF) -DACTIVATE_PROBES_A

CLEANFILES=probes.o
