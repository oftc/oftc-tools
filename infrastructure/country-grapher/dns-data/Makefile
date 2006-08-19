all: zone geo-map/irc geo-map/irc6 ip-to-country-map

zone:
	rsync -rvz countries-ns.mdc.dk::zone zone

ip-to-country-map: zone
	cat zone/zz.countries.nerd.dk.rbldnsd > $@

geo-map: iso2region.pl Makefile
	echo '$$RECORD irc' > $@
	echo '$$ORIGIN region.oftc.net' >> $@
	perl iso2region.pl | egrep -B1 '^[0-9]+ (eu|na|oc)$$' | grep -v -- '^--$$' >> $@

.PHONY: all zone
