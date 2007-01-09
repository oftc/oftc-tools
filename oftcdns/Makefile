.PHONY: all
all: ip2iso.cidr iso2ga.cdb

clean:
	rm -f ip2iso.cidr iso2ga.cdb
	rm -f ip2iso.txt  iso2ga.txt

maintainer-clean: clean
	rm -f ip2iso.txt iso2ga.txt

ip2iso.cidr: ip2iso.txt
	tail -n +2 $< | sed -e 's#:[[:digit:].]*:##' > $@

ip2iso.txt:
	rsync -rz countries-ns.mdc.dk::zone/zz.countries.nerd.dk.rbldnsd $@

iso2ga.cdb: iso2ga.txt
	grep -E "^AF|^AS|^EU|^NA|^SA|^AN|^OC" $< | awk '{print $$2, $$1}' | tr '[:upper:]' '[:lower:]' | cdb -cme $@

iso2ga.txt:
	wget -q -O $@ 'http://en.wikipedia.org/wiki/List_of_countries_by_continent_(data_file)' 
