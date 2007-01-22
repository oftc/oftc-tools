# Copyright (C) 2007 Luca Filipozzi
initdir=${sysconfdir}/init.d
etcdir=${sysconfdir}/${PACKAGE}
MAINTAINERCLEANFILES=aclocal.m4 config.guess config.log config.status configure install-sh missing mkinstalldirs Makefile.in INSTALL
init_SCRIPTS=oftcdns
etc_DATA=oftcdns.yaml exceptions_v4 exceptions_v6

clean-local:
	$(MAKE) -f oftcdns.mak clean

maintainer-clean-local:
	$(MAKE) -f oftcdns.mak maintainer-clean
	rm -f ${PACKAGE}-${VERSION}.tar.gz

