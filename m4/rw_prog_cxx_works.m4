# rw_PROG_CXX_WORKS
#
# Check whether the C++ compiler works. There's a bit of oversight in
# autoconf that will set the C++ compiler to g++ if no compiler is found,
# even if g++ is not present! So we need an extra test to make sure that
# the compiler works.
# Script copied from the lttng-ust project.
#
AC_DEFUN([rw_PROG_CXX_WORKS], [
AC_REQUIRE([AC_PROG_CXX])
AC_CACHE_CHECK([whether the C++ compiler works],
   [rw_cv_prog_cxx_works],
   [AC_LANG_PUSH([C++])

   AC_LINK_IFELSE([AC_LANG_PROGRAM([], [])], [
       check_cxx_designated_initializers=yes
   ], [
       rw_cv_prog_cxx_works=no
   ])

   AS_IF([test "x$check_cxx_designated_initializers" = "xyes"], [
       AC_COMPILE_IFELSE([AC_LANG_SOURCE([[
           struct foo { int a; int b; };
           void fct(void)
           {
               struct foo f = { .a = 0, .b = 1 };
           }
       ]])], [
           rw_cv_prog_cxx_works=yes
       ], [
           rw_cv_prog_cxx_works=no
       ])
   ])

   AC_LANG_POP([C++])
])
])
