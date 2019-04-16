# SYNOPSIS
#
#   RW_PROG_CXX_WORKS
#
# DESCRIPTION
#
#   RW_PROG_CXX_WORKS checks whether the C++ compiler works.
#
#   There's a bit of oversight in autoconf that will set the C++ compiler to
#   g++ if no compiler is found, even if g++ is not present! So we need an
#   extra test to make sure that the compiler works.
#
# LICENSE
#
#   Copying and distribution of this file, with or without modification, are
#   permitted in any medium without royalty provided the copyright notice
#   and this notice are preserved. This file is offered as-is, without any
#   warranty.

#serial 1

AC_DEFUN([RW_PROG_CXX_WORKS], [
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
