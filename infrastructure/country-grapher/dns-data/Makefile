all: zone geo-map ip-to-country-map

zone:
	rsync -rtvz countries-ns.mdc.dk::zone zone

ip-to-country-map: zone
	cat zone/zz.countries.nerd.dk.rbldnsd > $@

geo-map: iso2region.pl Makefile
	echo '$$RECORD irc' > $@
	echo '$$ORIGIN region.oftc.net' >> $@
	perl iso2region.pl >> $@

.PHONY: all zone
