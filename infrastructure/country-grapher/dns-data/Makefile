all: zone geo-map/irc geo-map/irc6 ip-to-country-map

zone:
	rsync -rvz countries-ns.mdc.dk::zone zone

ip-to-country-map: zone
	grep -v '^130.102.0.0/16' zone/zz.countries.nerd.dk.rbldnsd > $@
	# the university of queensland gets their own set of servers
	# that's because they don't have internet
	echo '130.102.0.0/16 :127.0.42.1:auUQ' >> $@

geo-map/irc: iso2region.pl Makefile
	echo '$$RECORD irc' > $@
	echo '$$ORIGIN region.oftc.net' >> $@
	perl iso2region.pl | egrep -B1 '^[0-9]+ (eu|na|oc)$$' | grep -v -- '^--$$' >> $@
	echo '# University of Queensland' >> $@
	echo '10753 uq.au' >> $@
	echo '0 global' >> $@

geo-map/irc6: iso2region.pl Makefile
	echo '$$RECORD irc6' > $@
	echo '$$ORIGIN region6.oftc.net' >> $@
	perl iso2region.pl | egrep -B1 '^[0-9]+ (eu|na|oc)$$' | grep -v -- '^--$$' >> $@
	echo '# University of Queensland' >> $@
	echo '10753 uq.au' >> $@
	echo '0 global' >> $@



.PHONY: all zone
