# ac_CHECK_SDT_WORKS
#
# Check whether it's possible to build a binary with Systemtap SDT probes.

AC_DEFUN([ax_CHECK_SDT_WORKS], [
AC_COMPILE_IFELSE(
[AC_LANG_SOURCE([[
		#define SDT_USE_VARIADIC
		#include <sys/sdt.h>
		void fct(void)
		{
			STAP_PROBEV(provider,name,1,2,3,4,5,6,7,8,9,10);
		}
	]])], [
		ax_check_sdt_works=yes
	], [
		ax_check_sdt_works=no
	]
)
])
