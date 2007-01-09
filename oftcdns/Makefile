.PHONY: all
all: ip2ga.cidr

.PHONY: clean
clean:
	rm -f ip2ga.cidr
	rm -f ip2iso.txt iso2ga.sed

.PHONY: maintainer-clean
maintainer-clean: clean
	rm -f ip2iso-pristine.txt iso2ga-pristine.txt


ip2iso-pristine.txt:
	rsync -rz countries-ns.mdc.dk::zone/zz.countries.nerd.dk.rbldnsd $@
iso2ga-pristine.txt:
	wget -q -O $@ 'http://en.wikipedia.org/wiki/List_of_countries_by_continent_(data_file)'

# I wonder how to make this one call the two items above, without making a simple 'make' always fetch new files
.PHONY: force-update
force-update:
	rsync -rz countries-ns.mdc.dk::zone/zz.countries.nerd.dk.rbldnsd ip2iso-pristine.txt
	wget -q -O iso2ga-pristine.txt 'http://en.wikipedia.org/wiki/List_of_countries_by_continent_(data_file)'


.INTERMEDIATE: ip2iso.txt
ip2iso.txt: ip2iso-pristine.txt
	tail -n +2 $< > $@

.INTERMEDIATE: iso2ga.sed
iso2ga.sed: iso2ga-pristine.txt
	grep -E "^AF|^AS|^EU|^NA|^SA|^AN|^OC" $< | \
		awk '{printf "s/ %s$$/ %s/\n", tolower($$2), $$1}' > $@
	echo 's/ eu$$/ EU/' >> $@
	echo 's/ uk$$/ EU/' >> $@
	echo 's/ yu$$/ EU/' >> $@

ip2ga.cidr: ip2iso.txt iso2ga.sed
	# we do this so we can catch errors later on
	if grep '[[:upper:]]' ip2iso.txt > /dev/null; then \
		echo && echo "precondition 'all strings lowercase' failed" && exit 1; \
	fi
	sed -e 's#[[:space:]][[:space:]]*:[[:digit:].]*:# #' -f iso2ga.sed  < ip2iso.txt > $@
	if grep '[[:lower:]]' "$@" > /dev/null; then \
		echo && echo "postcondition 'all strings uppercase' failed.  We probably did not map all countries to a continent" && exit 1; \
	fi
	# the university of queensland gets their own set of servers
	# that's because they don't have internet
	for prefix in \
		130.102.0.0/16 \
		152.98.192.0/18 \
		192.12.76.0/24 \
		203.15.32.0/19 \
		203.28.18.0/24 \
		203.101.224.0/19; do \
		if grep "^$$prefix " "$@" > /dev/null; then \
			sed -i "s#^$$prefix .*#$$prefix AUUQ#" "$@" || exit 1; \
		else \
			echo "$$prefix AUUQ" >> $@ || exit 1; \
		fi; \
	done

	# we do not have servers in all the regions
	sed -i 's/ \(AF\|AS\|SA\|AN\)$$/ global/' "$@"
