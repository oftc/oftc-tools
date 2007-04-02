# Copyright (C) 2007 Luca Filipozzi
MAINTAINERCLEANFILES=Makefile.in
dist_pkglib_SCRIPTS=convert aggregate validate
dist_pkglib_DATA=oftcdns.tac statbot.tac
etcdir=${sysconfdir}/${PACKAGE}
etc_DATA=oftcdns-schema.yaml oftcdns-example.yaml geo.example.com statbot-schema.yaml statbot-example.yaml
dist_etc_DATA=exceptions_v4 exceptions_v6
vardir=${localstatedir}/${PACKAGE}
var_DATA=oftcdns.mak

all-local: oftcdns-schema.yaml oftcdns-example.yaml statbot-schema.yaml statbot-example.yaml
	@kwalify -s -f oftcdns-schema.yaml oftcdns-example.yaml
	@kwalify -s -f statbot-schema.yaml statbot-example.yaml

maintainer-clean-local:
	${MAKE} -f oftcdns.mak.in maintainer-clean
