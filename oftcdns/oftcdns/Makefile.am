# Copyright (C) 2007 Luca Filipozzi
MAINTAINERCLEANFILES=Makefile.in
dist_pkglib_SCRIPTS=convert aggregate validate
dist_pkglib_DATA=oftcdns.tac
etcdir=${sysconfdir}/${PACKAGE}
etc_DATA=oftcdns.yaml
dist_etc_DATA=exceptions_v4 exceptions_v6
vardir=${localstatedir}/${PACKAGE}
var_DATA=oftcdns.mak

maintainer-clean-local:
	${MAKE} -f oftcdns.mak.in maintainer-clean
