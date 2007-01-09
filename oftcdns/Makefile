# the cdb binary can be found in the tinycdb debian package.

.PHONY: all
all: ip2ga.cidr

.PHONY: clean
clean:
	rm -f ip2iso-pristine.txt iso2ga-pristine.txt
	rm -f ip2iso.txt iso2ga.sed
	rm -f ip2ga.cidr

.PHONY: maintainer-clean
maintainer-clean: clean


ip2iso-pristine.txt:
	rsync -rz countries-ns.mdc.dk::zone/zz.countries.nerd.dk.rbldnsd $@

ip2iso.txt: ip2iso-pristine.txt
	# the university of queensland gets their own set of servers
	# that's because they don't have internet
	tail -n +2 $< > $@

iso2ga-pristine.txt:
	wget -q -O $@ 'http://en.wikipedia.org/wiki/List_of_countries_by_continent_(data_file)'

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
	for prefix in \
		130.102.0.0/16 \
		192.12.76.0/24 \
		203.11.224.0/18 \
		203.15.32.0/18 \
		203.28.18.0/24 \
		203.100.0.0/18; do \
		if grep '^$$prefix ' "$@" > /dev/null; then \
			sed -i "s#^$$prefix .*#$$prefix AUUQ#" "$@" || exit 1; \
		else \
			echo "$$prefix AUUQ" >> $@ || exit 1; \
		fi; \
	done


# these two files are fetched from remote locations, so we can't judge how up to date they are
# always update them
.PHONY: iso2ga-pristine.txt ip2iso-pristine.txt
