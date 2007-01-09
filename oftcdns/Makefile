# the cdb binary can be found in the tinycdb debian package.

.PHONY: all
all: ip2iso.cidr iso2ga.cdb

.PHONY: clean
clean:
	rm -f ip2iso.cidr iso2ga.cdb ip2iso-pristine.txt
	rm -f ip2iso.txt  iso2ga.txt

.PHONY: maintainer-clean
maintainer-clean: clean


ip2iso-pristine.txt:
	rsync -rz countries-ns.mdc.dk::zone/zz.countries.nerd.dk.rbldnsd $@

ip2iso.txt: ip2iso-pristine.txt
	# the university of queensland gets their own set of servers
	# that's because they don't have internet
	tail -n +2 $< | \
		egrep -v '^(130.102.0.0/16|192.12.76.0/24)' > $@
	echo '130.102.0.0/16  :0.0.0.0:auUQ' >> $@
	echo '192.12.76.0/24  :0.0.0.0:auUQ' >> $@
	echo '203.11.224.0/18 :0.0.0.0:auUQ' >> $@
	echo '203.15.32.0/18  :0.0.0.0:auUQ' >> $@
	echo '203.28.18.0/24  :0.0.0.0:auUQ' >> $@
	echo '203.100.0.0/18  :0.0.0.0:auUQ' >> $@

ip2iso.cidr: ip2iso.txt
	sed -e 's#[[:space:]][[:space:]]*:[[:digit:].]*:# #' < $< > $@



iso2ga.txt:
	wget -q -O $@ 'http://en.wikipedia.org/wiki/List_of_countries_by_continent_(data_file)'

iso2ga.cdb: iso2ga.txt
	grep -E "^AF|^AS|^EU|^NA|^SA|^AN|^OC" $< | \
		awk '{print $$2, $$1}' | \
		tr '[:upper:]' '[:lower:]' | \
		cdb -cme $@

# these two files are fetched from remote locations, so we can't judge how up to date they are
# always update them
.PHONY: iso2ga.txt ip2iso-pristine.txt
