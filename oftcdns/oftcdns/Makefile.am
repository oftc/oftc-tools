# Copyright (C) 2007 Luca Filipozzi
MAINTAINERCLEANFILES=Makefile.in
dist_pkglib_SCRIPTS=convert aggregate validate
dist_pkglib_DATA=oftcdns.tac
etcdir=${sysconfdir}/${PACKAGE}
etc_DATA=schema.yaml oftcdns-example.yaml geo.example.com
dist_etc_DATA=exceptions_v4 exceptions_v6
vardir=${localstatedir}/${PACKAGE}
var_DATA=oftcdns.mak

all-local: schema.yaml oftcdns-example.yaml
	@kwalify -s -f schema.yaml oftcdns-example.yaml

maintainer-clean-local:
	${MAKE} -f oftcdns.mak.in maintainer-clean

.PHONY: test
test: queries results
	dig @localhost -p 30053 -f queries +noquestion +noanswer +noauthority +noadditional +nostats +nocmd | sed -e 's#, id: [0-9]*$$##' | diff results -
