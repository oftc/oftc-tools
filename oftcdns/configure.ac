# Copyright (C) 2007 Luca Filipozzi
# vim: set fdm=marker ts=2 sw=2 et:

AC_PREREQ(2.59)
AC_INIT([oftcdns],[0.1])
AM_INIT_AUTOMAKE([oftcdns],[0.1])

AC_PROG_INSTALL
AX_PYTHON
AC_PYTHON_MODULE([IPy],[fatal])
AC_PYTHON_MODULE([radix],[fatal])
AC_PYTHON_MODULE([yaml],[fatal])
AC_PYTHON_MODULE([twisted],[fatal])

AC_DEFINE_DIR([LIBDIR],[libdir],[Set to libdir.])
AC_DEFINE_DIR([LOCALSTATEDIR],[localstatedir],[Set to localstatedir.])
AC_DEFINE_DIR([SYSCONFDIR],[sysconfdir],[Set to sysconfdir.])
AC_CONFIG_FILES([Makefile cron.d/Makefile cron.d/oftcdns init.d/Makefile init.d/oftcdns init.d/statbot oftcdns/Makefile oftcdns/oftcdns.mak oftcdns/oftcdns-example.yaml])
AC_OUTPUT
